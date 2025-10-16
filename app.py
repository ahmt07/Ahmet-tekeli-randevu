
import os
from datetime import datetime, timedelta, date, time
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from sqlalchemy import UniqueConstraint, and_
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DateField, TimeField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
db_path = os.path.join(os.path.dirname(__file__), 'data.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# ---- Settings ----
BUSINESS_OPEN_HOUR = int(os.getenv('BUSINESS_OPEN_HOUR', 9))
BUSINESS_CLOSE_HOUR = int(os.getenv('BUSINESS_CLOSE_HOUR', 21))
APPT_SLOT_MINUTES = int(os.getenv('APPT_SLOT_MINUTES', 30))
CANCEL_LIMIT_HOURS = int(os.getenv('CANCEL_LIMIT_HOURS', 2))

# ---- Models ----
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), default='customer')  # 'admin', 'barber', 'customer'
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    duration_min = db.Column(db.Integer, default=30)
    price = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

class Barber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='barber_profile')
    is_active = db.Column(db.Boolean, default=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    barber_id = db.Column(db.Integer, db.ForeignKey('barber.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    start_at = db.Column(db.DateTime, nullable=False, index=True)
    end_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='booked')  # 'booked','cancelled','completed'
    note = db.Column(db.String(255))

    customer = db.relationship('User', foreign_keys=[customer_id])
    barber = db.relationship('Barber')
    service = db.relationship('Service')

    __table_args__ = (
        UniqueConstraint('barber_id', 'start_at', name='uq_barber_start'),
    )

# ---- Forms ----
class RegisterForm(FlaskForm):
    name = StringField('Ad Soyad', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('E-posta', validators=[DataRequired(), Email()])
    phone = StringField('Telefon')
    password = PasswordField('Şifre', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Şifre (tekrar)', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Kayıt Ol')

    def validate_email(self, field):
        try:
            validate_email(field.data)
        except EmailNotValidError as e:
            raise ValidationError('Geçerli bir e-posta yazın.')
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Bu e-posta zaten kayıtlı.')

class LoginForm(FlaskForm):
    email = StringField('E-posta', validators=[DataRequired(), Email()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    remember = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class BookingForm(FlaskForm):
    service_id = SelectField('Hizmet', coerce=int, validators=[DataRequired()])
    barber_id = SelectField('Berber', coerce=int, validators=[DataRequired()])
    date = DateField('Tarih', validators=[DataRequired()])
    time = SelectField('Saat', coerce=str, validators=[DataRequired()])
    note = StringField('Not')
    submit = SubmitField('Randevu Al')

# ---- Login loader ----
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---- Utils ----
def time_slots_for_date(d: date, service_min: int):
    # returns list of datetime start times within business hours
    slots = []
    start_dt = datetime.combine(d, time(hour=BUSINESS_OPEN_HOUR))
    close_dt = datetime.combine(d, time(hour=BUSINESS_CLOSE_HOUR))
    step = timedelta(minutes=APPT_SLOT_MINUTES)
    while start_dt + timedelta(minutes=service_min) <= close_dt:
        slots.append(start_dt)
        start_dt += step
    return slots

def available_slots(d: date, barber_id: int, service_min: int):
    # get booked slots for this barber
    booked = {a.start_at for a in Appointment.query.filter(
        Appointment.barber_id==barber_id,
        Appointment.status=='booked',
        Appointment.start_at>=datetime.combine(d, time(0,0)),
        Appointment.start_at<datetime.combine(d+timedelta(days=1), time(0,0))
    ).all()}
    return [s for s in time_slots_for_date(d, service_min) if s not in booked]

def is_within_cancel_window(start_at: datetime):
    return datetime.utcnow() <= (start_at - timedelta(hours=CANCEL_LIMIT_HOURS))

# ---- Routes ----
@app.route('/')
def index():
    services = Service.query.filter_by(is_active=True).all()
    barbers = Barber.query.join(User).filter(Barber.is_active==True).all()
    return render_template('index.html', services=services, barbers=barbers)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, email=form.email.data.lower(), phone=form.phone.data, role='customer')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Kayıt tamamlandı. Hoş geldiniz!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Giriş başarılı.', 'success')
            return redirect(url_for('dashboard'))
        flash('E-posta veya şifre hatalı.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Çıkış yapıldı.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin' or current_user.role == 'barber':
        # Admin / Barber view shows today's schedule summary
        today = date.today()
        appts = Appointment.query.filter(
            Appointment.start_at>=datetime.combine(today, time(0,0)),
            Appointment.start_at<datetime.combine(today+timedelta(days=1), time(0,0))
        ).order_by(Appointment.start_at.asc()).all()
        return render_template('admin_dashboard.html', appts=appts, today=today)
    else:
        # Customer view
        my_appts = Appointment.query.filter_by(customer_id=current_user.id).order_by(Appointment.start_at.desc()).all()
        return render_template('customer_dashboard.html', appts=my_appts)

@app.route('/book', methods=['GET','POST'])
@login_required
def book():
    form = BookingForm()
    form.service_id.choices = [(s.id, f"{s.name} ({s.duration_min} dk)") for s in Service.query.filter_by(is_active=True)]
    form.barber_id.choices = [(b.id, b.user.name) for b in Barber.query.join(User).filter(Barber.is_active==True)]
    # default times list (populated via JS on change as well)
    service_min = Service.query.filter_by(id=form.service_id.data).first().duration_min if form.service_id.data else APPT_SLOT_MINUTES
    d = form.date.data or date.today()
    times = [dt.strftime('%H:%M') for dt in available_slots(d, form.barber_id.data, service_min)] if (form.barber_id.data and form.date.data) else []
    form.time.choices = [(t,t) for t in times]

    if form.validate_on_submit():
        service = Service.query.get(form.service_id.data)
        d = form.date.data
        start_time = datetime.strptime(form.time.data, '%H:%M').time()
        start_at = datetime.combine(d, start_time)
        end_at = start_at + timedelta(minutes=service.duration_min)
        # enforce uniqueness for the chosen barber/time
        existing = Appointment.query.filter_by(barber_id=form.barber_id.data, start_at=start_at, status='booked').first()
        if existing:
            flash('Seçilen saat bu berber için dolu. Lütfen başka bir saat seçin.', 'warning')
            return redirect(url_for('book'))
        appt = Appointment(customer_id=current_user.id, barber_id=form.barber_id.data, service_id=service.id,
                           start_at=start_at, end_at=end_at, note=form.note.data)
        db.session.add(appt)
        db.session.commit()
        flash('Randevunuz oluşturuldu.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('book.html', form=form)

@app.route('/slots')
def slots_api():
    # AJAX: /slots?barber_id=1&service_id=1&date=2025-10-16
    try:
        barber_id = int(request.args.get('barber_id'))
        service_id = int(request.args.get('service_id'))
        d = datetime.strptime(request.args.get('date'), '%Y-%m-%d').date()
    except Exception:
        return jsonify({'error': 'Parametre hatası'}), 400
    service = Service.query.get(service_id)
    slots = [dt.strftime('%H:%M') for dt in available_slots(d, barber_id, service.duration_min)]
    return jsonify({'slots': slots})

@app.route('/appointment/<int:appt_id>/cancel', methods=['POST'])
@login_required
def cancel_appt(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    if current_user.role == 'customer' and appt.customer_id != current_user.id:
        abort(403)
    if appt.status != 'booked':
        flash('Bu randevu zaten güncel değil.', 'warning')
        return redirect(url_for('dashboard'))
    if current_user.role == 'customer' and not is_within_cancel_window(appt.start_at):
        flash(f'Randevuya {CANCEL_LIMIT_HOURS} saatten az kaldı. Müşteri iptal edemez.', 'danger')
        return redirect(url_for('dashboard'))
    appt.status='cancelled'
    db.session.commit()
    flash('Randevu iptal edildi.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/appointment/<int:appt_id>/reschedule', methods=['POST'])
@login_required
def reschedule_appt(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    if current_user.role == 'customer' and appt.customer_id != current_user.id:
        abort(403)
    # parse new date/time
    new_date = request.form.get('new_date')
    new_time = request.form.get('new_time')
    try:
        nd = datetime.strptime(new_date, '%Y-%m-%d').date()
        nt = datetime.strptime(new_time, '%H:%M').time()
    except Exception:
        flash('Yeni tarih/saat geçersiz.', 'danger')
        return redirect(url_for('dashboard'))
    service = appt.service
    start_at = datetime.combine(nd, nt)
    # prevent double-book for the same barber
    existing = Appointment.query.filter_by(barber_id=appt.barber_id, start_at=start_at, status='booked').first()
    if existing:
        flash('Bu saat bu berber için dolu.', 'warning')
        return redirect(url_for('dashboard'))
    appt.start_at = start_at
    appt.end_at = start_at + timedelta(minutes=service.duration_min)
    db.session.commit()
    flash('Randevu güncellendi.', 'success')
    return redirect(url_for('dashboard'))

# ---- Admin area ----
def admin_required():
    if not current_user.is_authenticated or current_user.role != 'admin':
        abort(403)

@app.route('/admin/settings', methods=['GET','POST'])
@login_required
def admin_settings():
    admin_required()
    # Allow edit of hours and slot minutes via form
    global BUSINESS_OPEN_HOUR, BUSINESS_CLOSE_HOUR, APPT_SLOT_MINUTES, CANCEL_LIMIT_HOURS
    if request.method == 'POST':
        BUSINESS_OPEN_HOUR = int(request.form.get('open_hour', BUSINESS_OPEN_HOUR))
        BUSINESS_CLOSE_HOUR = int(request.form.get('close_hour', BUSINESS_CLOSE_HOUR))
        APPT_SLOT_MINUTES = int(request.form.get('slot_min', APPT_SLOT_MINUTES))
        CANCEL_LIMIT_HOURS = int(request.form.get('cancel_limit', CANCEL_LIMIT_HOURS))
        flash('Ayarlar güncellendi.', 'success')
    return render_template('admin_settings.html',
                           open_hour=BUSINESS_OPEN_HOUR,
                           close_hour=BUSINESS_CLOSE_HOUR,
                           slot_min=APPT_SLOT_MINUTES,
                           cancel_limit=CANCEL_LIMIT_HOURS)

@app.route('/admin/manage', methods=['GET','POST'])
@login_required
def admin_manage():
    admin_required()
    # Manage services and barbers
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_service':
            name = request.form['name']
            duration = int(request.form['duration'])
            price = int(request.form['price'])
            db.session.add(Service(name=name, duration_min=duration, price=price))
            db.session.commit()
            flash('Hizmet eklendi.', 'success')
        elif action == 'toggle_service':
            s = Service.query.get(int(request.form['id']))
            s.is_active = not s.is_active
            db.session.commit()
            flash('Hizmet güncellendi.', 'info')
        elif action == 'add_barber':
            name = request.form['name']
            email = request.form['email'].lower()
            password = request.form['password']
            if User.query.filter_by(email=email).first():
                flash('Bu e-posta zaten kullanılıyor.', 'danger')
            else:
                u = User(name=name, email=email, role='barber')
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                db.session.add(Barber(user_id=u.id))
                db.session.commit()
                flash('Berber eklendi.', 'success')
        elif action == 'toggle_barber':
            b = Barber.query.get(int(request.form['id']))
            b.is_active = not b.is_active
            db.session.commit()
            flash('Berber güncellendi.', 'info')
    services = Service.query.order_by(Service.is_active.desc(), Service.name).all()
    barbers = Barber.query.join(User).order_by(Barber.is_active.desc(), User.name).all()
    return render_template('admin_manage.html', services=services, barbers=barbers)

@app.route('/admin/reports')
@login_required
def admin_reports():
    admin_required()
    # Simple KPI: appointments count per day, revenue estimate
    from collections import defaultdict
    appts = Appointment.query.filter(Appointment.status=='booked').order_by(Appointment.start_at.desc()).all()
    daily_counts = defaultdict(int)
    revenue = 0
    for a in appts:
        key = a.start_at.date().isoformat()
        daily_counts[key] += 1
        revenue += a.service.price
    sorted_days = sorted(daily_counts.items(), key=lambda x: x[0], reverse=True)
    return render_template('admin_reports.html', appts=appts, daily_counts=sorted_days, revenue=revenue)

# ---- CLI/init ----
@app.cli.command('initdb')
def initdb():
    """Initialize database with default admin, services, and one barber."""
    db.create_all()
    # Create admin if not exists
    admin_email = 'admin@ahmet-tekeli.com'
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(name='Ahmet Tekeli (Admin)', email=admin_email, role='admin')
        admin.set_password('admin123')  # change after first login
        db.session.add(admin)
        db.session.commit()
    # Create sample barber
    barber_email = 'aziz@ahmet-tekeli.com'
    barber_user = User.query.filter_by(email=barber_email).first()
    if not barber_user:
        barber_user = User(name='Aziz Usta', email=barber_email, role='barber')
        barber_user.set_password('berber123')
        db.session.add(barber_user)
        db.session.commit()
        db.session.add(Barber(user_id=barber_user.id))
    # Create default services
    if Service.query.count() == 0:
        db.session.add_all([
            Service(name='Saç Kesim', duration_min=30, price=300),
            Service(name='Sakal', duration_min=20, price=200),
            Service(name='Saç + Sakal', duration_min=60, price=450),
        ])
    db.session.commit()
    print('Veritabanı hazır. Admin: admin@ahmet-tekeli.com / şifre: admin123')

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(db_path):
            db.create_all()
    app.run(debug=True)
