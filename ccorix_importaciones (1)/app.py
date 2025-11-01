
from flask import (Flask, render_template, request, redirect, url_for, session, flash,
                   send_from_directory, abort, make_response)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, DecimalField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, NumberRange, EqualTo
import sqlite3, os, uuid
from functools import wraps
from datetime import datetime

# Optional WeasyPrint import (may require extra system packages)
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'ccorix.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 4 * 1024 * 1024  # 4MB

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cambia_esta_clave_por_una_segura')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
csrf = CSRFProtect(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        created_at TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price REAL,
        stock INTEGER,
        image TEXT,
        created_at TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        total REAL,
        created_at TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS invoice_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id INTEGER,
        product_id INTEGER,
        qty INTEGER,
        price REAL
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        path TEXT,
        ip TEXT,
        ua TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    cur.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cur.fetchone():
        cur.execute('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)',
                    ('admin', generate_password_hash('Admin!234'), 'admin', datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()

init_db()

def log_access(user, path):
    conn = get_db(); cur = conn.cursor()
    ip = request.remote_addr or 'unknown'; ua = request.headers.get('User-Agent','')
    cur.execute('INSERT INTO access_logs (user, path, ip, ua, timestamp) VALUES (?,?,?,?,?)',
                (user or 'anon', path, ip, ua, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def unique_filename(filename):
    ext = filename.rsplit('.',1)[1] if '.' in filename else ''
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Necesitas iniciar sesión.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'role' not in session or session.get('role') not in roles:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6), EqualTo('confirm', message='Las contraseñas deben coincidir')])
    confirm = PasswordField('Repetir contraseña')
    role = SelectField('Rol', choices=[('buyer','Comprador'),('employee','Empleado')], default='buyer')
    submit = SubmitField('Registrar')

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class ProductForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Descripción')
    price = DecimalField('Precio', validators=[DataRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Guardar')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Contraseña actual', validators=[DataRequired()])
    new_password = PasswordField('Nueva contraseña', validators=[DataRequired(), Length(min=6), EqualTo('confirm', message='Las contraseñas deben coincidir')])
    confirm = PasswordField('Repetir nueva contraseña')
    submit = SubmitField('Cambiar')

@app.route('/')
def index():
    log_access(session.get('username'), '/')
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip(); password = form.password.data; role = form.role.data
        conn = get_db(); cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)',
                        (username, generate_password_hash(password), role, datetime.utcnow().isoformat()))
            conn.commit(); flash('Usuario creado. Inicia sesión.', 'success'); return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe.', 'danger')
        finally:
            conn.close()
    return render_template('auth/register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip(); password = form.password.data
        conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone(); conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']; session['username'] = user['username']; session['role'] = user['role']
            flash(f'Bienvenido {user["username"]}', 'success'); log_access(user['username'], '/login'); return redirect(url_for('index'))
        flash('Credenciales inválidas.', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/logout')
def logout():
    log_access(session.get('username'), '/logout'); session.clear(); flash('Sesión cerrada.', 'info'); return redirect(url_for('login'))

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current = form.current_password.data; new = form.new_password.data
        conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = cur.fetchone()
        if user and check_password_hash(user['password'], current):
            cur.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(new), session['user_id'])); conn.commit(); conn.close()
            flash('Contraseña actualizada.', 'success'); return redirect(url_for('index'))
        conn.close(); flash('Contraseña actual incorrecta.', 'danger')
    return render_template('auth/change_password.html', form=form)

@app.route('/products')
@login_required
def products_list():
    q = request.args.get('q','').strip(); page = max(int(request.args.get('page',1)),1); per_page = 8; offset = (page-1)*per_page
    conn = get_db(); cur = conn.cursor(); params = []
    sql = 'SELECT * FROM products WHERE stock > 0'
    if q:
        sql += ' AND (name LIKE ? OR description LIKE ?)'; params += [f'%{q}%', f'%{q}%']
    sql_count = 'SELECT COUNT(*) as cnt FROM ('+sql+')'
    cur.execute(sql_count, params); total = cur.fetchone()['cnt']
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'; params += [per_page, offset]
    cur.execute(sql, params); products = cur.fetchall(); conn.close()
    total_pages = (total + per_page - 1)//per_page; log_access(session.get('username'), '/products')
    return render_template('products/list.html', products=products, q=q, page=page, total_pages=total_pages)

@app.route('/admin/products')
@login_required
@role_required(['admin','manager','employee'])
def admin_products():
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM products ORDER BY created_at DESC'); products = cur.fetchall(); conn.close()
    return render_template('products/admin_list.html', products=products)

@app.route('/admin/product/new', methods=['GET','POST'])
@login_required
@role_required(['admin','manager'])
def admin_new_product():
    form = ProductForm()
    if form.validate_on_submit():
        file = request.files.get('image'); filename = None
        if file and file.filename and allowed_file(file.filename):
            filename = unique_filename(secure_filename(file.filename)); file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        conn = get_db(); cur = conn.cursor()
        cur.execute('INSERT INTO products (name, description, price, stock, image, created_at) VALUES (?,?,?,?,?,?)',
                    (form.name.data, form.description.data, float(form.price.data), int(form.stock.data), filename, datetime.utcnow().isoformat()))
        conn.commit(); conn.close(); flash('Producto creado.', 'success'); return redirect(url_for('admin_products'))
    return render_template('products/form.html', form=form)

@app.route('/admin/product/<int:pid>/edit', methods=['GET','POST'])
@login_required
@role_required(['admin','manager'])
def admin_edit_product(pid):
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM products WHERE id = ?', (pid,)); product = cur.fetchone()
    if not product: conn.close(); abort(404)
    form = ProductForm(data=product)
    if form.validate_on_submit():
        file = request.files.get('image'); filename = product['image']
        if file and file.filename and allowed_file(file.filename):
            filename = unique_filename(secure_filename(file.filename)); file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        cur.execute('UPDATE products SET name=?, description=?, price=?, stock=?, image=? WHERE id=?',
                    (form.name.data, form.description.data, float(form.price.data), int(form.stock.data), filename, pid))
        conn.commit(); conn.close(); flash('Producto actualizado.', 'success'); return redirect(url_for('admin_products'))
    conn.close(); return render_template('products/form.html', form=form, product=product)

@app.route('/admin/product/<int:pid>/delete', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_delete_product(pid):
    conn = get_db(); cur = conn.cursor(); cur.execute('DELETE FROM products WHERE id = ?', (pid,)); conn.commit(); conn.close()
    flash('Producto eliminado.', 'info'); return redirect(url_for('admin_products'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/cart')
@login_required
def cart_view():
    cart = session.get('cart', {}); products=[]; total=0.0
    if cart:
        conn = get_db(); cur = conn.cursor()
        for pid_str, qty in cart.items():
            pid = int(pid_str); cur.execute('SELECT * FROM products WHERE id = ?', (pid,)); p = cur.fetchone()
            if p:
                item_total = p['price'] * qty; products.append({'product': p, 'qty': qty, 'total': item_total}); total += item_total
        conn.close()
    return render_template('cart/cart.html', items=products, total=total)

@app.route('/cart/add/<int:pid>', methods=['POST'])
@login_required
def cart_add(pid):
    qty = max(1, int(request.form.get('qty',1)))
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT stock FROM products WHERE id = ?', (pid,)); p = cur.fetchone(); conn.close()
    if not p or p['stock'] < qty: flash('No hay suficiente stock.', 'danger'); return redirect(url_for('products_list'))
    cart = session.get('cart', {}); cart[str(pid)] = cart.get(str(pid), 0) + qty; session['cart'] = cart
    flash('Producto agregado al carrito.', 'success'); return redirect(url_for('products_list'))

@app.route('/cart/remove/<int:pid>', methods=['POST'])
@login_required
def cart_remove(pid):
    cart = session.get('cart', {}); cart.pop(str(pid), None); session['cart'] = cart
    flash('Producto eliminado del carrito.', 'info'); return redirect(url_for('cart_view'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart: flash('Carrito vacío.', 'warning'); return redirect(url_for('cart_view'))
    conn = get_db(); cur = conn.cursor(); total=0.0; items=[]
    for pid_str, qty in cart.items():
        pid=int(pid_str); cur.execute('SELECT * FROM products WHERE id = ?', (pid,)); p = cur.fetchone()
        if not p or p['stock'] < qty: conn.close(); flash('Stock insuficiente para algunos productos.', 'danger'); return redirect(url_for('cart_view'))
        total += p['price'] * qty; items.append((pid, qty, p['price']))
    cur.execute('INSERT INTO invoices (user_id, total, created_at) VALUES (?,?,?)', (session['user_id'], total, datetime.utcnow().isoformat()))
    invoice_id = cur.lastrowid
    for pid, qty, price in items:
        cur.execute('INSERT INTO invoice_items (invoice_id, product_id, qty, price) VALUES (?,?,?,?)', (invoice_id, pid, qty, price))
        cur.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (qty, pid))
    conn.commit(); conn.close(); session['cart'] = {}; flash('Compra realizada. Aquí está la factura.', 'success')
    return redirect(url_for('invoice_view', invoice_id=invoice_id))

@app.route('/invoice/<int:invoice_id>')
@login_required
def invoice_view(invoice_id):
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)); invoice = cur.fetchone()
    if not invoice: conn.close(); abort(404)
    cur.execute('SELECT ii.*, p.name FROM invoice_items ii JOIN products p ON ii.product_id = p.id WHERE ii.invoice_id = ?', (invoice_id,))
    items = cur.fetchall(); conn.close()
    return render_template('invoice/invoice.html', invoice=invoice, items=items)

@app.route('/invoice/pdf/<int:invoice_id>')
@login_required
def invoice_pdf(invoice_id):
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)); invoice = cur.fetchone()
    if not invoice: conn.close(); abort(404)
    cur.execute('SELECT ii.*, p.name FROM invoice_items ii JOIN products p ON ii.product_id = p.id WHERE ii.invoice_id = ?', (invoice_id,))
    items = cur.fetchall(); conn.close()
    html = render_template('invoice/invoice_pdf.html', invoice=invoice, items=items)
    if WEASYPRINT_AVAILABLE:
        pdf = HTML(string=html).write_pdf()
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=invoice_{invoice_id}.pdf'
        return response
    else:
        flash('WeasyPrint no está instalado en el servidor. La factura se mostrará en pantalla y puedes imprimirla con el botón.', 'warning')
        return render_template('invoice/invoice.html', invoice=invoice, items=items)

@app.route('/admin/logs')
@login_required
@role_required(['admin'])
def view_logs():
    conn = get_db(); cur = conn.cursor(); cur.execute('SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 500'); logs = cur.fetchall(); conn.close()
    return render_template('admin/logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
