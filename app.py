import qrcode
import os
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from datetime import date

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from db import get_db_connection

from io import BytesIO

from flask import make_response

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=1800
)

# Enable CSRF protection after configuring the secret key
csrf = CSRFProtect(app)


def log_audit(table_name, operation, record_id, description):

    conn = get_db_connection()

    if conn is None:
        print("Audit logging failed: Database connection unavailable.")
        return

    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO audit_log (
                table_name,
                operation,
                record_id,
                changed_by,
                changed_at,
                description
            )
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, %s);
        """, (
            table_name,
            operation,
            str(record_id),
            session.get("user_id"),
            description
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Audit logging error:", e)

    finally:
        cursor.close()
        conn.close()



def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            # 1. Check whether the user is logged in
            if "user_id" not in session:
                return redirect(url_for("login"))

            conn = get_db_connection()

            if conn is None:
                flash("Unable to verify your account. Please try again.")
                return redirect(url_for("login"))

            cursor = conn.cursor()

            try:
                # 2. Verify the user's current account status and role
                cursor.execute("""
                    SELECT au.is_active, r.role_name
                    FROM app_user au
                    JOIN role r
                        ON au.role_id = r.role_id
                    WHERE au.user_id = %s;
                """, (session["user_id"],))

                user = cursor.fetchone()

            except Exception as e:
                conn.rollback()
                print("Session verification error:", e)
                flash("Unable to verify your account. Please try again.")
                return redirect(url_for("login"))

            finally:
                cursor.close()
                conn.close()

            # 3. Check whether the account still exists and is active
            if not user or not user[0]:
                session.clear()
                flash("Your account is inactive or unavailable. Please contact the administrator.")
                return redirect(url_for("login"))

            # 4. Update the session with the current database role
            current_role = user[1]
            session["role"] = current_role

            # 5. Check whether the current role has permission
            if current_role not in allowed_roles:
                flash("Access denied! You do not have permission.")
                return redirect(url_for("dashboard"))

            # 6. Allow access
            return function(*args, **kwargs)

        return wrapper

    return decorator



@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()

        if conn is None:
            flash("Database connection failed.")
            return render_template("login.html")

        cursor = conn.cursor()

        cursor.execute("""
            SELECT au.user_id, au.username, au.full_name,
                   au.password_hash, au.is_active, r.role_name
            FROM app_user au
            JOIN role r ON au.role_id = r.role_id
            WHERE au.username = %s;
        """, (username,))

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password_hash(user[3], password):

            # Check whether the account is active
            if not user[4]:
                flash("Your account has been deactivated. Contact the administrator.")
                return redirect(url_for("login"))

            # Clear previous session data
            session.clear()

            # Store user information in session
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["full_name"] = user[2]
            session["role"] = user[5]

            # Enable permanent session (30-minute lifetime)
            session.permanent = True

            return redirect(url_for("dashboard"))

        else:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

    return render_template("login.html")



@app.route("/dashboard")
@role_required(
    "Admin",
    "Manufacturer",
    "Distributor",
    "Service Center",
    "Recycler",
    "Customer"
)
def dashboard():

    role = session["role"]

    role_features = {
        "Admin": [
            ("User Management", "Manage application users and roles."),
            ("Product Management", "Search and inspect all registered products."),
            ("Lifecycle Monitoring", "Monitor product lifecycle events."),
            ("Maintenance Records", "Review product servicing records."),
            ("Recycling Analytics", "Review recycling and recovery performance.")
        ],

        "Manufacturer": [
            ("Product Management", "View your registered products."),
            ("Lifecycle Monitoring", "Review manufacturing and distribution history."),
            ("Material Information", "Explore product components and materials.")
        ],

        "Distributor": [
            ("Product Search", "Find and inspect product passports."),
            ("Lifecycle Monitoring", "Review distribution and sale history.")
        ],

        "Service Center": [
            ("Product Search", "Find products requiring service."),
            ("Maintenance Records", "Review maintenance and repair history.")
        ],

        "Recycler": [
            ("Product Search", "Find products ready for recycling."),
            ("Recycling Analytics", "Review recovered materials and recovery rates.")
        ],

        "Customer": [
            ("Product Search", "Explore your product's digital passport."),
            ("Product Information", "View materials, ownership and sustainability details.")
        ]
    }

    features = role_features.get(role, [])

    return render_template(
        "dashboard.html",
        full_name=session["full_name"],
        role=role,
        features=features
    )

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))



@app.route("/search", methods=["GET", "POST"])
@role_required(
    "Admin",
    "Manufacturer",
    "Distributor",
    "Service Center",
    "Recycler",
    "Customer"
)
def search_product():

    product = None
    materials = []
    lifecycle = []
    ownership = []
    maintenance = []
    recycling = []
    searched = False

    if request.method == "POST":
        product_id = request.form.get("product_id", "").strip().upper()
        searched = True

        conn = get_db_connection()

        if conn is None:
            flash("Unable to connect to the database.")
        else:
            cursor = conn.cursor()

            try:
                # 1. Main product information
                cursor.execute("""
                    SELECT *
                    FROM complete_dpp_report
                    WHERE product_id = %s;
                """, (product_id,))

                result = cursor.fetchone()

                if result:
                    columns = [desc[0] for desc in cursor.description]
                    product = dict(zip(columns, result))

                    # 2. Material and component information
                    cursor.execute("""
                        SELECT
                            c.component_name,
                            m.material_name,
                            m.material_category,
                            c.quantity,
                            c.unit,
                            m.origin,
                            m.recyclable,
                            m.recyclability_percentage,
                            m.carbon_impact_kg
                        FROM component c
                        JOIN material m
                            ON c.material_id = m.material_id
                        WHERE c.product_id = %s
                        ORDER BY c.component_id;
                    """, (product_id,))

                    columns = [desc[0] for desc in cursor.description]
                    materials = [
                        dict(zip(columns, row))
                        for row in cursor.fetchall()
                    ]

                    # 3. Lifecycle history for visual timeline
                    cursor.execute("""
                        SELECT
                            event_id,
                            event_type,
                            event_date,
                            location,
                            description
                        FROM lifecycle_event
                        WHERE product_id = %s
                        ORDER BY event_date ASC, event_id ASC;
                    """, (product_id,))

                    columns = [desc[0] for desc in cursor.description]
                    lifecycle = [
                        dict(zip(columns, row))
                        for row in cursor.fetchall()
                    ]

                    # 4. Ownership history
                    cursor.execute("""
                        SELECT
                            owner_name,
                            owner_type,
                            start_date,
                            end_date,
                            transfer_reason
                        FROM ownership
                        WHERE product_id = %s
                        ORDER BY start_date;
                    """, (product_id,))

                    columns = [desc[0] for desc in cursor.description]
                    ownership = [
                        dict(zip(columns, row))
                        for row in cursor.fetchall()
                    ]

                    # 5. Maintenance history
                    cursor.execute("""
                        SELECT
                            maintenance_date,
                            maintenance_type,
                            description,
                            technician_name,
                            service_center,
                            cost
                        FROM maintenance
                        WHERE product_id = %s
                        ORDER BY maintenance_date;
                    """, (product_id,))

                    columns = [desc[0] for desc in cursor.description]
                    maintenance = [
                        dict(zip(columns, row))
                        for row in cursor.fetchall()
                    ]

                    # 6. Recycling information
                    cursor.execute("""
                        SELECT
                            recycling_date,
                            recycling_facility,
                            recycling_method,
                            recovered_material,
                            recovered_quantity,
                            recovery_percentage
                        FROM recycling
                        WHERE product_id = %s
                        ORDER BY recycling_date;
                    """, (product_id,))

                    columns = [desc[0] for desc in cursor.description]
                    recycling = [
                        dict(zip(columns, row))
                        for row in cursor.fetchall()
                    ]

            except Exception as e:
                conn.rollback()
                print("Product search error:", e)
                flash("Something went wrong while retrieving product details.")

            finally:
                cursor.close()
                conn.close()

    return render_template(
        "search.html",
        product=product,
        materials=materials,
        lifecycle=lifecycle,
        ownership=ownership,
        maintenance=maintenance,
        recycling=recycling,
        searched=searched
    )
@app.route("/admin-panel")
@role_required("Admin")
def admin_panel():
    return """
        <h1>Admin Control Panel</h1>
        <p>Access granted!</p>
        <p>Only Admin users can access this page.</p>
        <a href="/dashboard">Back to Dashboard</a>
    """

@app.route("/maintenance-panel")
@role_required("Admin", "Service Center")
def maintenance_panel():
    return """
        <h1>Maintenance Control Panel</h1>
        <p>Access granted to Admin or Service Center.</p>
        <a href="/dashboard">Back to Dashboard</a>
    """


@app.route("/recycling-panel")
@role_required("Admin", "Recycler")
def recycling_panel():
    return """
        <h1>Recycling Control Panel</h1>
        <p>Access granted to Admin or Recycler.</p>
        <a href="/dashboard">Back to Dashboard</a>
    """

@app.route("/admin-users")
@role_required("Admin")
def admin_users():

    connection = get_db_connection()

    if connection is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            u.user_id,
            u.username,
            u.full_name,
            u.email,
            r.role_name,
            u.is_active
        FROM app_user u
        JOIN role r
        ON u.role_id = r.role_id
        ORDER BY u.user_id;
    """)

    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template("admin_users.html", users=users)


@app.route("/toggle-user/<int:user_id>", methods=["POST"])
@role_required("Admin")
def toggle_user(user_id):

    # Prevent Admin from deactivating their own account
    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.")
        return redirect(url_for("admin_users"))

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("admin_users"))

    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE app_user
            SET is_active = NOT is_active
            WHERE user_id = %s;
        """, (user_id,))

        if cursor.rowcount == 0:
            conn.rollback()
            flash("User account not found.")
        else:
            conn.commit()
            flash("User account status updated successfully!")

    except Exception as e:
        conn.rollback()
        print("Toggle user error:", e)
        flash("Could not update user account status.")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/add-user", methods=["GET", "POST"])
@role_required("Admin")
def add_user():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("admin_users"))

    cursor = conn.cursor()

    try:
        # Fetch available roles
        cursor.execute("""
            SELECT role_id, role_name
            FROM role
            ORDER BY role_id;
        """)
        roles = cursor.fetchall()

        # Fetch registered manufacturers
        cursor.execute("""
            SELECT manufacturer_id, manufacturer_name
            FROM manufacturer
            ORDER BY manufacturer_name;
        """)
        manufacturers = cursor.fetchall()

        if request.method == "POST":

            username = request.form.get("username", "").strip()
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role_id = request.form.get("role_id", "").strip()
            manufacturer_id = request.form.get("manufacturer_id", "").strip()

            # Basic validation
            if not all([username, full_name, email, password, role_id]):
                flash("Please fill in all required fields.")
                return render_template(
                    "add_user.html",
                    roles=roles,
                    manufacturers=manufacturers
                )

            if len(password) < 8:
                flash("Password must contain at least 8 characters.")
                return render_template(
                    "add_user.html",
                    roles=roles,
                    manufacturers=manufacturers
                )

            if "@" not in email:
                flash("Please enter a valid email address.")
                return render_template(
                    "add_user.html",
                    roles=roles,
                    manufacturers=manufacturers
                )

            # Validate selected role
            cursor.execute("""
                SELECT role_name
                FROM role
                WHERE role_id = %s;
            """, (role_id,))

            selected_role = cursor.fetchone()

            if not selected_role:
                flash("Invalid role selected.")
                return render_template(
                    "add_user.html",
                    roles=roles,
                    manufacturers=manufacturers
                )

            role_name = selected_role[0]

            # Manufacturer accounts must be linked to a company
            if role_name == "Manufacturer":

                if not manufacturer_id:
                    flash("Please select a manufacturer company.")
                    return render_template(
                        "add_user.html",
                        roles=roles,
                        manufacturers=manufacturers
                    )

                cursor.execute("""
                    SELECT manufacturer_id
                    FROM manufacturer
                    WHERE manufacturer_id = %s;
                """, (manufacturer_id,))

                if not cursor.fetchone():
                    flash("Invalid manufacturer selected.")
                    return render_template(
                        "add_user.html",
                        roles=roles,
                        manufacturers=manufacturers
                    )

            else:
                manufacturer_id = None

            # Check duplicate username or email
            cursor.execute("""
                SELECT user_id
                FROM app_user
                WHERE username = %s OR email = %s;
            """, (username, email))

            if cursor.fetchone():
                flash("Username or email already exists.")
                return render_template(
                    "add_user.html",
                    roles=roles,
                    manufacturers=manufacturers
                )

            # Securely hash the password
            password_hash = generate_password_hash(password)

            # Create the user account
            cursor.execute("""
                INSERT INTO app_user (
                    username,
                    full_name,
                    email,
                    password_hash,
                    role_id,
                    manufacturer_id,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                RETURNING user_id;
            """, (
                username,
                full_name,
                email,
                password_hash,
                role_id,
                manufacturer_id
            ))

            new_user_id = cursor.fetchone()[0]

            conn.commit()

            # Record user creation in audit log
            log_audit(
                "app_user",
                "INSERT",
                new_user_id,
                f"New {role_name} account created: {username}."
            )

            flash("New user account created successfully!")
            return redirect(url_for("admin_users"))

    except Exception as e:
        conn.rollback()
        print("Add user error:", e)
        flash("Could not create user. Please check the entered details.")

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "add_user.html",
        roles=roles,
        manufacturers=manufacturers
    )

@app.route("/audit-logs")
@role_required("Admin")
def audit_logs():

    table_filter = request.args.get("table_name", "")
    operation_filter = request.args.get("operation", "")
    user_filter = request.args.get("changed_by", "")

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    logs = []
    table_options = []
    user_options = []

    insert_count = 0
    update_count = 0
    delete_count = 0

    try:
        # 1. Get available table names
        cursor.execute("""
            SELECT DISTINCT table_name
            FROM audit_log
            ORDER BY table_name;
        """)

        table_options = [
            row[0] for row in cursor.fetchall()
        ]

        # 2. Get available users
        cursor.execute("""
            SELECT DISTINCT au.user_id, au.username
            FROM audit_log a
            JOIN app_user au
                ON a.changed_by = au.user_id
            ORDER BY au.username;
        """)

        user_options = cursor.fetchall()

        # 3. Build the audit log query
        query = """
            SELECT
                a.audit_id,
                a.table_name,
                a.operation,
                a.record_id,
                au.username,
                a.changed_at,
                a.description
            FROM audit_log a
            LEFT JOIN app_user au
                ON a.changed_by = au.user_id
        """

        conditions = []
        values = []

        if table_filter:
            conditions.append("a.table_name = %s")
            values.append(table_filter)

        if operation_filter:
            conditions.append("a.operation = %s")
            values.append(operation_filter)

        if user_filter and user_filter.isdigit():
            conditions.append("a.changed_by = %s")
            values.append(int(user_filter))

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.changed_at DESC;"

        # 4. Execute the query
        cursor.execute(query, tuple(values))

        columns = [
            desc[0] for desc in cursor.description
        ]

        logs = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        # 5. Calculate operation counts
        insert_count = sum(
            1 for log in logs
            if log["operation"] == "INSERT"
        )

        update_count = sum(
            1 for log in logs
            if log["operation"] == "UPDATE"
        )

        delete_count = sum(
            1 for log in logs
            if log["operation"] == "DELETE"
        )

    except Exception as e:
        print("Audit log retrieval error:", e)
        flash("Unable to retrieve audit logs.")

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "audit_logs.html",
        logs=logs,
        table_options=table_options,
        user_options=user_options,
        table_filter=table_filter,
        operation_filter=operation_filter,
        user_filter=user_filter,
        insert_count=insert_count,
        update_count=update_count,
        delete_count=delete_count
    )

@app.route("/add-maintenance", methods=["GET", "POST"])
@role_required("Admin", "Service Center")
def add_maintenance():

    if request.method == "POST":

        product_id = request.form.get("product_id", "").strip()
        maintenance_date = request.form.get("maintenance_date")
        maintenance_type = request.form.get("maintenance_type")
        description = request.form.get("description", "").strip()
        technician_name = request.form.get("technician_name", "").strip()
        service_center = request.form.get("service_center", "").strip()
        cost = request.form.get("cost")

        conn = get_db_connection()

        if conn is None:
            flash("Database connection failed.")
            return redirect(url_for("add_maintenance"))

        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO maintenance
                (
                    product_id,
                    maintenance_date,
                    maintenance_type,
                    description,
                    technician_name,
                    service_center,
                    cost
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (
                product_id,
                maintenance_date,
                maintenance_type,
                description,
                technician_name,
                service_center,
                cost
            ))

            conn.commit()
            log_audit(
                "maintenance",
                "INSERT",
                product_id,
                f"Maintenance record added for product {product_id}."
                )
            flash("Maintenance record added successfully!")

        except Exception as e:
            conn.rollback()
            print("Maintenance insertion error:", e)
            flash("Could not add maintenance record. Check the product ID and entered details.")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("add_maintenance"))

    return render_template("add_maintenance.html")


@app.route("/add-recycling", methods=["GET", "POST"])
@role_required("Admin", "Recycler")
def add_recycling():

    if request.method == "POST":

        product_id = request.form.get("product_id", "").strip()
        recycling_date = request.form.get("recycling_date")
        recycling_facility = request.form.get("recycling_facility", "").strip()
        recycling_method = request.form.get("recycling_method", "").strip()
        recovered_material = request.form.get("recovered_material", "").strip()
        recovered_quantity = request.form.get("recovered_quantity")
        recovery_percentage = request.form.get("recovery_percentage")

        conn = get_db_connection()

        if conn is None:
            flash("Database connection failed.")
            return redirect(url_for("add_recycling"))

        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO recycling
                (
                    product_id,
                    recycling_date,
                    recycling_facility,
                    recycling_method,
                    recovered_material,
                    recovered_quantity,
                    recovery_percentage
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (
                product_id,
                recycling_date,
                recycling_facility,
                recycling_method,
                recovered_material,
                recovered_quantity,
                recovery_percentage
            ))

            conn.commit()
            log_audit(
                "recycling",
                "INSERT",
                product_id,
                f"Recycling record added for product {product_id}."
                )
            flash("Recycling record added successfully!")

        except Exception as e:
            conn.rollback()
            print("Recycling insertion error:", e)
            flash("Could not add recycling record. Check the product ID and entered details.")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("add_recycling"))

    return render_template("add_recycling.html")


@app.route("/manufacturer-products")
@role_required("Manufacturer")
def manufacturer_products():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        # Identify the company linked to the logged-in manufacturer
        cursor.execute("""
            SELECT manufacturer_id
            FROM app_user
            WHERE user_id = %s;
        """, (session["user_id"],))

        manufacturer = cursor.fetchone()

        if not manufacturer or manufacturer[0] is None:
            flash("No manufacturer is linked to this account.")
            return redirect(url_for("dashboard"))

        manufacturer_id = manufacturer[0]

        # Retrieve only products belonging to that company
        cursor.execute("""
            SELECT
                product_id,
                product_name,
                product_type,
                model_number,
                production_date,
                warranty_end_date,
                status
            FROM product
            WHERE manufacturer_id = %s
            ORDER BY product_id;
        """, (manufacturer_id,))

        products = cursor.fetchall()

        cursor.execute("""
            SELECT manufacturer_name, location
            FROM manufacturer
            WHERE manufacturer_id = %s;
        """, (manufacturer_id,))

        company = cursor.fetchone()

    except Exception as e:
        print("Manufacturer products error:", e)
        flash("Could not retrieve manufacturer products.")
        return redirect(url_for("dashboard"))

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "manufacturer_products.html",
        products=products,
        company=company
    )




@app.route("/register-product", methods=["GET", "POST"])
@role_required("Manufacturer")
def register_product():

    if request.method == "POST":

        product_id = request.form.get("product_id", "").strip()
        product_name = request.form.get("product_name", "").strip()
        product_type = request.form.get("product_type", "").strip()
        model_number = request.form.get("model_number", "").strip()
        production_date = request.form.get("production_date", "").strip()
        warranty_end_date = request.form.get("warranty_end_date", "").strip()

        # Validate required fields
        if not all([
            product_id,
            product_name,
            product_type,
            model_number,
            production_date,
            warranty_end_date
        ]):
            flash("Please fill in all required product details.")
            return redirect(url_for("register_product"))

        # Validate dates
        try:
            production = date.fromisoformat(production_date)
            warranty = date.fromisoformat(warranty_end_date)

            if warranty < production:
                flash("Warranty end date cannot be before production date.")
                return redirect(url_for("register_product"))

        except ValueError:
            flash("Please enter valid production and warranty dates.")
            return redirect(url_for("register_product"))

        conn = get_db_connection()

        if conn is None:
            flash("Database connection failed.")
            return redirect(url_for("register_product"))

        cursor = conn.cursor()

        try:
            # Get manufacturer ID from logged-in account
            cursor.execute("""
                SELECT manufacturer_id
                FROM app_user
                WHERE user_id = %s;
            """, (session["user_id"],))

            manufacturer = cursor.fetchone()

            if not manufacturer or manufacturer[0] is None:
                flash("No manufacturer is linked to this account.")
                return redirect(url_for("dashboard"))

            manufacturer_id = manufacturer[0]

            # Register product
            cursor.execute("""
                INSERT INTO product (
                    product_id,
                    product_name,
                    product_type,
                    model_number,
                    manufacturer_id,
                    production_date,
                    warranty_end_date,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'Manufactured');
            """, (
                product_id,
                product_name,
                product_type,
                model_number,
                manufacturer_id,
                production_date,
                warranty_end_date
            ))

            conn.commit()

            # Record operation in audit log
            log_audit(
                "product",
                "INSERT",
                product_id,
                f"New product {product_name} registered by manufacturer."
            )

            flash("Product registered successfully!")

        except Exception as e:
            conn.rollback()
            print("Product registration error:", e)
            flash(
                "Could not register product. "
                "Check for duplicate Product ID or Model Number."
            )

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("manufacturer_products"))

    return render_template("register_product.html")


@app.route("/add-component", methods=["GET", "POST"])
@role_required("Manufacturer")
def add_component():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        # Get the logged-in manufacturer's ID
        cursor.execute("""
            SELECT manufacturer_id
            FROM app_user
            WHERE user_id = %s;
        """, (session["user_id"],))

        manufacturer = cursor.fetchone()

        if not manufacturer or manufacturer[0] is None:
            flash("No manufacturer is linked to this account.")
            return redirect(url_for("dashboard"))

        manufacturer_id = manufacturer[0]

        # Fetch only this manufacturer's products
        cursor.execute("""
            SELECT product_id, product_name
            FROM product
            WHERE manufacturer_id = %s
            ORDER BY product_id;
        """, (manufacturer_id,))

        products = cursor.fetchall()

        # Fetch all available materials
        cursor.execute("""
            SELECT material_id, material_name
            FROM material
            ORDER BY material_id;
        """)

        materials = cursor.fetchall()

        if request.method == "POST":

            product_id = request.form.get("product_id")
            material_id = request.form.get("material_id")
            component_name = request.form.get("component_name", "").strip()
            quantity = request.form.get("quantity")
            unit = request.form.get("unit", "").strip()

            # Verify product ownership
            cursor.execute("""
                SELECT product_id
                FROM product
                WHERE product_id = %s
                  AND manufacturer_id = %s;
            """, (product_id, manufacturer_id))

            valid_product = cursor.fetchone()

            if not valid_product:
                flash("Invalid product selection.")
                return render_template(
                    "add_component.html",
                    products=products,
                    materials=materials
                )

            cursor.execute("""
                INSERT INTO component (
                    product_id,
                    material_id,
                    component_name,
                    quantity,
                    unit
                )
                VALUES (%s, %s, %s, %s, %s);
            """, (
                product_id,
                material_id,
                component_name,
                quantity,
                unit
            ))

            conn.commit()
            flash("Component added successfully!")

            return redirect(url_for("add_component"))

    except Exception as e:
        conn.rollback()
        print("Add component error:", e)
        flash("Could not add component. Please check the entered details.")

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "add_component.html",
        products=products,
        materials=materials
    )


@app.route("/add-lifecycle-event", methods=["GET", "POST"])
@role_required("Manufacturer")
def add_lifecycle_event():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        # Identify the logged-in manufacturer
        cursor.execute("""
            SELECT manufacturer_id
            FROM app_user
            WHERE user_id = %s;
        """, (session["user_id"],))

        manufacturer = cursor.fetchone()

        if not manufacturer or manufacturer[0] is None:
            flash("No manufacturer is linked to this account.")
            return redirect(url_for("dashboard"))

        manufacturer_id = manufacturer[0]

        # Fetch products belonging to this manufacturer
        cursor.execute("""
            SELECT product_id, product_name
            FROM product
            WHERE manufacturer_id = %s
            ORDER BY product_id;
        """, (manufacturer_id,))

        products = cursor.fetchall()

        if request.method == "POST":

            product_id = request.form.get("product_id")
            event_type = request.form.get("event_type")
            event_date = request.form.get("event_date")
            location = request.form.get("location", "").strip()
            description = request.form.get("description", "").strip()

            # Verify that the product belongs to this manufacturer
            cursor.execute("""
                SELECT product_id
                FROM product
                WHERE product_id = %s
                  AND manufacturer_id = %s;
            """, (product_id, manufacturer_id))

            valid_product = cursor.fetchone()

            if not valid_product:
                flash("Invalid product selection.")
                return render_template(
                    "add_lifecycle_event.html",
                    products=products
                )

            # Insert lifecycle event
            cursor.execute("""
                INSERT INTO lifecycle_event (
                    product_id,
                    event_type,
                    event_date,
                    location,
                    description,
                    recorded_by
                )
                VALUES (%s, %s, %s, %s, %s, %s);
            """, (
                product_id,
                event_type,
                event_date,
                location,
                description,
                session["user_id"]
            ))

            conn.commit()
            flash("Lifecycle event added successfully!")

            return redirect(url_for("add_lifecycle_event"))

    except Exception as e:
        conn.rollback()
        print("Lifecycle event error:", e)
        flash("Could not add lifecycle event. Please check the details.")

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "add_lifecycle_event.html",
        products=products
    )


@app.route("/add-ownership", methods=["GET", "POST"])
@role_required("Manufacturer")
def add_ownership():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        # Identify logged-in manufacturer
        cursor.execute("""
            SELECT manufacturer_id
            FROM app_user
            WHERE user_id = %s;
        """, (session["user_id"],))

        manufacturer = cursor.fetchone()

        if not manufacturer or manufacturer[0] is None:
            flash("No manufacturer is linked to this account.")
            return redirect(url_for("dashboard"))

        manufacturer_id = manufacturer[0]

        # Fetch manufacturer's products
        cursor.execute("""
            SELECT product_id, product_name
            FROM product
            WHERE manufacturer_id = %s
            ORDER BY product_id;
        """, (manufacturer_id,))

        products = cursor.fetchall()

        if request.method == "POST":

            product_id = request.form.get("product_id")
            owner_name = request.form.get("owner_name", "").strip()
            owner_type = request.form.get("owner_type")
            start_date = request.form.get("start_date")
            end_date = request.form.get("end_date") or None
            transfer_reason = request.form.get("transfer_reason", "").strip()

            # Verify product belongs to manufacturer
            cursor.execute("""
                SELECT product_id
                FROM product
                WHERE product_id = %s
                  AND manufacturer_id = %s;
            """, (product_id, manufacturer_id))

            valid_product = cursor.fetchone()

            if not valid_product:
                flash("Invalid product selection.")
                return render_template(
                    "add_ownership.html",
                    products=products
                )

            # Validate ownership dates
            if end_date and end_date < start_date:
                flash("End date cannot be earlier than start date.")
                return render_template(
                    "add_ownership.html",
                    products=products
                )

            # Insert ownership record
            cursor.execute("""
                INSERT INTO ownership (
                    product_id,
                    owner_name,
                    owner_type,
                    start_date,
                    end_date,
                    transfer_reason
                )
                VALUES (%s, %s, %s, %s, %s, %s);
            """, (
                product_id,
                owner_name,
                owner_type,
                start_date,
                end_date,
                transfer_reason
            ))

            conn.commit()
            log_audit(
                "ownership",
                "INSERT",
                product_id,
                f"Ownership record added for product {product_id} by {owner_name}."
                )
            flash("Ownership record added successfully!")

            return redirect(url_for("add_ownership"))

    except Exception as e:
        conn.rollback()
        print("Ownership registration error:", e)
        flash("Could not add ownership record. Please check the details.")

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "add_ownership.html",
        products=products
    )



@app.route("/update-product-status/<product_id>", methods=["POST"])
@role_required("Manufacturer")
def update_product_status(product_id):

    allowed_statuses = [
        "Manufactured",
        "Distributed",
        "In Use",
        "Under Maintenance",
        "Refurbished",
        "Recycled"
    ]

    new_status = request.form.get("status")

    if new_status not in allowed_statuses:
        flash("Invalid product status.")
        return redirect(url_for("manufacturer_products"))

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("manufacturer_products"))

    cursor = conn.cursor()

    try:
        # Get the logged-in manufacturer's ID
        cursor.execute("""
            SELECT manufacturer_id
            FROM app_user
            WHERE user_id = %s;
        """, (session["user_id"],))

        manufacturer = cursor.fetchone()

        if not manufacturer or manufacturer[0] is None:
            flash("No manufacturer is linked to this account.")
            return redirect(url_for("dashboard"))

        manufacturer_id = manufacturer[0]

        # Get the previous product status
        cursor.execute("""
            SELECT status
            FROM product
            WHERE product_id = %s
              AND manufacturer_id = %s;
        """, (product_id, manufacturer_id))

        old_status = cursor.fetchone()

        if old_status is None:
            flash("Product not found or access denied.")

        else:
            # Update product status
            cursor.execute("""
                UPDATE product
                SET status = %s
                WHERE product_id = %s
                  AND manufacturer_id = %s;
            """, (new_status, product_id, manufacturer_id))

            if cursor.rowcount == 0:
                conn.rollback()
                flash("Product not found or access denied.")

            else:
                conn.commit()

                # Record status update in audit log
                log_audit(
                    "product",
                    "UPDATE",
                    product_id,
                    f"Product status changed from {old_status[0]} to {new_status}."
                )

                flash("Product status updated successfully!")

    except Exception as e:
        conn.rollback()
        print("Product status update error:", e)
        flash("Could not update product status.")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("manufacturer_products"))



@app.route("/admin-analytics")
@role_required("Admin")
def admin_analytics():

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        # 1. Basic system statistics
        cursor.execute("SELECT COUNT(*) FROM product;")
        total_products = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM manufacturer;")
        total_manufacturers = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM app_user;")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM lifecycle_event;")
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM maintenance;")
        total_maintenance = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM recycling;")
        total_recycling = cursor.fetchone()[0]

        # 2. Product status distribution
        cursor.execute("""
            SELECT status, COUNT(*)
            FROM product
            GROUP BY status
            ORDER BY status;
        """)

        status_data = cursor.fetchall()
        status_labels = [row[0] for row in status_data]
        status_values = [row[1] for row in status_data]

        # 3. Recycling performance by material
        cursor.execute("""
            SELECT recovered_material, SUM(recovered_quantity)
            FROM recycling
            GROUP BY recovered_material
            ORDER BY recovered_material;
        """)

        recycling_data = cursor.fetchall()
        recycling_labels = [row[0] for row in recycling_data]
        recycling_values = [
            float(row[1] or 0) for row in recycling_data
        ]

        # 4. Manufacturer performance
        cursor.execute("""
            SELECT
                m.manufacturer_name,
                COUNT(p.product_id)
            FROM manufacturer m
            LEFT JOIN product p
                ON m.manufacturer_id = p.manufacturer_id
            GROUP BY m.manufacturer_id, m.manufacturer_name
            ORDER BY COUNT(p.product_id) DESC;
        """)

        manufacturer_data = cursor.fetchall()
        manufacturer_labels = [row[0] for row in manufacturer_data]
        manufacturer_values = [row[1] for row in manufacturer_data]

        # 5. Lifecycle activity by event type
        cursor.execute("""
            SELECT event_type, COUNT(*)
            FROM lifecycle_event
            GROUP BY event_type
            ORDER BY event_type;
        """)

        lifecycle_data = cursor.fetchall()
        lifecycle_labels = [row[0] for row in lifecycle_data]
        lifecycle_values = [row[1] for row in lifecycle_data]

        # 6. Total maintenance expenditure
        cursor.execute("""
            SELECT COALESCE(SUM(cost), 0)
            FROM maintenance;
        """)

        maintenance_total_cost = float(cursor.fetchone()[0] or 0)

        # 7. Sustainability overview
        cursor.execute("""
            SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE recyclable = TRUE),
                COALESCE(AVG(recyclability_percentage), 0)
            FROM material;
        """)

        sustainability_data = cursor.fetchone()

        total_materials = sustainability_data[0]
        recyclable_materials = sustainability_data[1]
        average_recyclability = float(sustainability_data[2] or 0)

        # 8. Average recycling recovery percentage
        cursor.execute("""
            SELECT COALESCE(AVG(recovery_percentage), 0)
            FROM recycling;
        """)

        average_recovery = float(cursor.fetchone()[0] or 0)

    except Exception as e:
        conn.rollback()
        print("Analytics error:", e)
        flash("Unable to retrieve analytics.")
        return redirect(url_for("dashboard"))

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_analytics.html",
        total_products=total_products,
        total_manufacturers=total_manufacturers,
        total_users=total_users,
        total_events=total_events,
        total_maintenance=total_maintenance,
        total_recycling=total_recycling,
        status_labels=status_labels,
        status_values=status_values,
        recycling_labels=recycling_labels,
        recycling_values=recycling_values,
        manufacturer_labels=manufacturer_labels,
        manufacturer_values=manufacturer_values,
        lifecycle_labels=lifecycle_labels,
        lifecycle_values=lifecycle_values,
        maintenance_total_cost=maintenance_total_cost,
        total_materials=total_materials,
        recyclable_materials=recyclable_materials,
        average_recyclability=average_recyclability,
        average_recovery=average_recovery
    )

@app.route("/generate-qr/<product_id>")
@role_required(
    "Admin",
    "Manufacturer",
    "Distributor",
    "Service Center",
    "Recycler",
    "Customer"
)
def generate_qr(product_id):

    conn = get_db_connection()

    if conn is None:
        flash("Database connection failed.")
        return redirect(url_for("dashboard"))

    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT product_id
            FROM product
            WHERE product_id = %s;
        """, (product_id,))

        product = cursor.fetchone()

        if not product:
            flash("Product not found.")
            return redirect(url_for("search_product"))

        # Generate the product passport URL
        passport_url = url_for(
            "public_passport",
            product_id=product_id,
            _external=True
        )

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=4
        )

        qr.add_data(passport_url)
        qr.make(fit=True)

        qr_image = qr.make_image(
            fill_color="black",
            back_color="white"
        )

        # Create QR code folder if it doesn't exist
        qr_folder = os.path.join(
            app.root_path,
            "static",
            "qrcodes"
        )

        os.makedirs(qr_folder, exist_ok=True)

        # Save QR code image
        qr_path = os.path.join(
            qr_folder,
            f"{product_id}.png"
        )

        qr_image.save(qr_path)

        flash("QR code generated successfully!")

        return render_template(
            "qr_code.html",
            product_id=product_id,
            qr_image=f"qrcodes/{product_id}.png",
            passport_url=passport_url
        )

    except Exception as e:
        print("QR generation error:", e)
        flash("Unable to generate QR code.")

        return redirect(url_for("dashboard"))

    finally:
        cursor.close()
        conn.close()


@app.route("/public-passport/<product_id>")
def public_passport(product_id):

    conn = get_db_connection()

    if conn is None:
        return "Database connection failed.", 500

    cursor = conn.cursor()

    try:
        # 1. Get product information
        cursor.execute("""
            SELECT *
            FROM complete_dpp_report
            WHERE product_id = %s;
        """, (product_id,))

        result = cursor.fetchone()

        if not result:
            return "Product not found.", 404

        columns = [
            desc[0] for desc in cursor.description
        ]

        product = dict(zip(columns, result))

        # 2. Get component and material information
        cursor.execute("""
            SELECT
                c.component_name,
                m.material_name,
                m.material_category,
                c.quantity,
                c.unit,
                m.origin,
                m.recyclable,
                m.recyclability_percentage,
                m.carbon_impact_kg
            FROM component c
            JOIN material m
                ON c.material_id = m.material_id
            WHERE c.product_id = %s
            ORDER BY c.component_id;
        """, (product_id,))

        columns = [
            desc[0] for desc in cursor.description
        ]

        materials = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        # 3. Get lifecycle history
        cursor.execute("""
            SELECT
                event_type,
                event_date,
                location,
                description
            FROM lifecycle_event
            WHERE product_id = %s
            ORDER BY event_date, event_id;
        """, (product_id,))

        columns = [
            desc[0] for desc in cursor.description
        ]

        lifecycle = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        # 4. Get ownership history
        cursor.execute("""
            SELECT
                owner_name,
                owner_type,
                start_date,
                end_date,
                transfer_reason
            FROM ownership
            WHERE product_id = %s
            ORDER BY start_date;
        """, (product_id,))

        columns = [
            desc[0] for desc in cursor.description
        ]

        ownership = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        # 5. Get maintenance history
        cursor.execute("""
            SELECT
                maintenance_date,
                maintenance_type,
                description,
                technician_name,
                service_center,
                cost
            FROM maintenance
            WHERE product_id = %s
            ORDER BY maintenance_date;
        """, (product_id,))

        columns = [
            desc[0] for desc in cursor.description
        ]

        maintenance = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        # 6. Get recycling information
        cursor.execute("""
            SELECT
                recycling_date,
                recycling_facility,
                recycling_method,
                recovered_material,
                recovered_quantity,
                recovery_percentage
            FROM recycling
            WHERE product_id = %s
            ORDER BY recycling_date;
        """, (product_id,))

        columns = [
            desc[0] for desc in cursor.description
        ]

        recycling = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

        return render_template(
            "public_passport.html",
            product=product,
            materials=materials,
            lifecycle=lifecycle,
            ownership=ownership,
            maintenance=maintenance,
            recycling=recycling
        )

    except Exception as e:
        print("Public passport error:", e)
        return "Unable to retrieve product passport.", 500

    finally:
        cursor.close()
        conn.close()


@app.route("/download-passport/<product_id>")
def download_passport(product_id):

    conn = get_db_connection()

    if conn is None:
        return "Database connection failed.", 500

    cursor = conn.cursor()

    try:
        # 1. Retrieve product information
        cursor.execute("""
            SELECT *
            FROM complete_dpp_report
            WHERE product_id = %s;
        """, (product_id,))

        result = cursor.fetchone()

        if not result:
            return "Product not found.", 404

        columns = [desc[0] for desc in cursor.description]
        product = dict(zip(columns, result))

        # 2. Retrieve materials and components
        cursor.execute("""
            SELECT
                c.component_name,
                m.material_name,
                m.material_category,
                c.quantity,
                c.unit,
                m.origin,
                m.recyclable,
                m.recyclability_percentage,
                m.carbon_impact_kg
            FROM component c
            JOIN material m
                ON c.material_id = m.material_id
            WHERE c.product_id = %s
            ORDER BY c.component_id;
        """, (product_id,))

        materials = cursor.fetchall()

        # 3. Retrieve lifecycle history
        cursor.execute("""
            SELECT event_type, event_date, location, description
            FROM lifecycle_event
            WHERE product_id = %s
            ORDER BY event_date, event_id;
        """, (product_id,))

        lifecycle = cursor.fetchall()

        # 4. Retrieve ownership history
        cursor.execute("""
            SELECT owner_name, owner_type, start_date,
                   end_date, transfer_reason
            FROM ownership
            WHERE product_id = %s
            ORDER BY start_date;
        """, (product_id,))

        ownership = cursor.fetchall()

        # 5. Retrieve maintenance history
        cursor.execute("""
            SELECT maintenance_date, maintenance_type,
                   description, technician_name,
                   service_center, cost
            FROM maintenance
            WHERE product_id = %s
            ORDER BY maintenance_date;
        """, (product_id,))

        maintenance = cursor.fetchall()

        # 6. Retrieve recycling history
        cursor.execute("""
            SELECT recycling_date, recycling_facility,
                   recycling_method, recovered_material,
                   recovered_quantity, recovery_percentage
            FROM recycling
            WHERE product_id = %s
            ORDER BY recycling_date;
        """, (product_id,))

        recycling = cursor.fetchall()

        # 7. Prepare PDF in memory
        buffer = BytesIO()

        pdf = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DigiPassTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#286b50"),
            fontSize=22,
            spaceAfter=8
        )

        heading_style = ParagraphStyle(
            "DigiPassHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#286b50"),
            spaceBefore=14,
            spaceAfter=8
        )

        normal_style = styles["BodyText"]

        story = []

        story.append(Paragraph(
            "DigiPass - Digital Product Passport",
            title_style
        ))

        story.append(Paragraph(
            "Product Transparency, Traceability & Sustainability",
            normal_style
        ))

        story.append(Spacer(1, 15))

        # 8. Product overview
        story.append(Paragraph("Product Overview", heading_style))

        overview = [
            ["Product ID", product.get("product_id") or "N/A"],
            ["Product Name", product.get("product_name") or "N/A"],
            ["Product Type", product.get("product_type") or "N/A"],
            ["Model Number", product.get("model_number") or "N/A"],
            ["Manufacturer", product.get("manufacturer_name") or "N/A"],
            ["Manufacturer Location", product.get("manufacturer_location") or "N/A"],
            ["Production Date", str(product.get("production_date") or "N/A")],
            ["Warranty End Date", str(product.get("warranty_end_date") or "N/A")],
            ["Current Status", product.get("status") or "N/A"]
        ]

        overview_table = Table(
            overview,
            colWidths=[48 * mm, 115 * mm]
        )

        overview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf4ed")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#20372c")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        story.append(overview_table)

        # 9. Materials and components
        story.append(Paragraph("Materials & Components", heading_style))

        material_data = [[
            "Component", "Material", "Quantity", "Origin", "Recyclable"
        ]]

        for row in materials:
            material_data.append([
                str(row[0] or "N/A"),
                str(row[1] or "N/A"),
                f"{row[3] or 0} {row[4] or ''}",
                str(row[5] or "N/A"),
                str(row[6] if row[6] is not None else "N/A")
            ])

        material_table = Table(
            material_data,
            colWidths=[34 * mm, 32 * mm, 28 * mm, 37 * mm, 32 * mm],
            repeatRows=1
        )

        material_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#286b50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        if materials:
            story.append(material_table)
        else:
            story.append(Paragraph("No material records available.", normal_style))

        # 10. Lifecycle history
        story.append(Paragraph("Product Lifecycle History", heading_style))

        lifecycle_data = [["Event", "Date", "Location", "Description"]]

        for row in lifecycle:
            lifecycle_data.append([
                str(row[0] or "N/A"),
                str(row[1] or "N/A"),
                str(row[2] or "N/A"),
                str(row[3] or "N/A")
            ])

        if lifecycle:
            table = Table(
                lifecycle_data,
                colWidths=[35 * mm, 28 * mm, 40 * mm, 60 * mm],
                repeatRows=1
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#286b50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No lifecycle records available.", normal_style))

        # 11. Ownership history
        story.append(Paragraph("Ownership History", heading_style))

        ownership_data = [[
            "Owner", "Type", "Start Date", "End Date", "Reason"
        ]]

        for row in ownership:
            ownership_data.append([
                str(row[0] or "N/A"),
                str(row[1] or "N/A"),
                str(row[2] or "N/A"),
                str(row[3] or "Current"),
                str(row[4] or "N/A")
            ])

        if ownership:
            table = Table(
                ownership_data,
                colWidths=[34 * mm, 25 * mm, 28 * mm, 28 * mm, 48 * mm],
                repeatRows=1
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#286b50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No ownership records available.", normal_style))

        # 12. Maintenance history
        story.append(Paragraph("Maintenance & Repair History", heading_style))

        maintenance_data = [[
            "Date", "Type", "Description", "Technician", "Service Center", "Cost"
        ]]

        for row in maintenance:
            maintenance_data.append([
                str(row[0] or "N/A"),
                str(row[1] or "N/A"),
                str(row[2] or "N/A"),
                str(row[3] or "N/A"),
                str(row[4] or "N/A"),
                str(row[5] if row[5] is not None else "N/A")
            ])

        if maintenance:
            table = Table(
                maintenance_data,
                colWidths=[23 * mm, 25 * mm, 42 * mm, 27 * mm, 29 * mm, 17 * mm],
                repeatRows=1
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#286b50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
                ("FONTSIZE", (0, 0), (-1, -1), 6),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No maintenance records available.", normal_style))

        # 13. Recycling history
        story.append(Paragraph("Recycling & Sustainability", heading_style))

        recycling_data = [[
            "Date", "Facility", "Method", "Recovered Material", "Quantity", "Recovery %"
        ]]

        for row in recycling:
            recycling_data.append([
                str(row[0] or "N/A"),
                str(row[1] or "N/A"),
                str(row[2] or "N/A"),
                str(row[3] or "N/A"),
                str(row[4] if row[4] is not None else "N/A"),
                str(row[5] if row[5] is not None else "N/A")
            ])

        if recycling:
            table = Table(
                recycling_data,
                colWidths=[23 * mm, 32 * mm, 27 * mm, 35 * mm, 23 * mm, 23 * mm],
                repeatRows=1
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#286b50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce5dc")),
                ("FONTSIZE", (0, 0), (-1, -1), 6),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No recycling records available.", normal_style))

        # 14. Generate PDF
        pdf.build(story)

        buffer.seek(0)

        response = make_response(buffer.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="DigiPass_{product_id}.pdf"'
        )

        return response

    except Exception as e:
        print("PDF generation error:", e)
        return "Unable to generate product passport PDF.", 500

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    app.run(debug=True)
