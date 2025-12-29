from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
from PIL import Image
import os
import uuid
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///neoshare_new.db'
app.config['UPLOAD_FOLDER'] = 'uploads_new'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'public'), exist_ok=True)

# 初始化数据库
db = SQLAlchemy(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(80), default='')
    avatar = db.Column(db.String(200), default='default.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(400), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    file_size = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 路由定义
@app.route('/')
def index():
    # 获取公共文件列表
    public_files = File.query.filter_by(is_public=True).all()
    return render_template('new_index.html', public_files=public_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and sha256_crypt.verify(password, user.password):
            if user.is_banned:
                flash('您的账号已被封禁', 'danger')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('用户名或密码错误', 'danger')
    return render_template('new_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('两次输入的密码不一致', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = sha256_crypt.hash(password)
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        # 创建用户个人文件夹
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], str(user.id)), exist_ok=True)
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template('new_register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # 获取用户个人文件
    user_files = File.query.filter_by(owner_id=current_user.id).all()
    # 获取公共文件
    public_files = File.query.filter_by(is_public=True).all()
    return render_template('new_dashboard.html', user_files=user_files, public_files=public_files)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('new_admin.html', users=users)

@app.route('/ban_user/<int:user_id>')
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get(user_id)
    if user and not user.is_admin:
        user.is_banned = True
        db.session.commit()
    return redirect(url_for('admin'))

@app.route('/unban_user/<int:user_id>')
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get(user_id)
    if user:
        user.is_banned = False
        db.session.commit()
    return redirect(url_for('admin'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user.nickname = request.form['nickname']
        
        # 处理头像上传
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename != '':
                # 生成唯一文件名
                filename = f"{uuid.uuid4()}_{file.filename}"
                filepath = os.path.join('static/images', filename)
                # 保存头像
                file.save(filepath)
                current_user.avatar = filename
        
        db.session.commit()
        flash('设置已更新', 'success')
        return redirect(url_for('settings'))
    return render_template('new_settings.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('没有选择文件', 'danger')
        return redirect(request.referrer)
    
    file = request.files['file']
    if file.filename == '':
        flash('没有选择文件', 'danger')
        return redirect(request.referrer)
    
    is_public = request.form.get('is_public') == 'on'
    
    if current_user.is_authenticated:
        # 登录用户，可以上传到个人目录或公共目录
        if is_public:
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'public')
        else:
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    else:
        # 未登录用户，只能上传到公共目录
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'public')
        is_public = True
    
    # 保存文件
    filename = file.filename
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)
    
    # 记录到数据库
    file_size = os.path.getsize(filepath)
    new_file = File(
        filename=filename,
        filepath=filepath,
        owner_id=current_user.id if current_user.is_authenticated else None,
        is_public=is_public,
        file_size=file_size
    )
    db.session.add(new_file)
    db.session.commit()
    
    flash('文件上传成功', 'success')
    return redirect(request.referrer)

@app.route('/files/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/preview/<int:file_id>')
def preview_file(file_id):
    file = File.query.get_or_404(file_id)
    content = ''
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    # 读取文本文件内容
    if ext in ['txt', 'md', 'markdown', 'py', 'js', 'html', 'css', 'json', 'xml', 'yaml', 'yml', 'sh', 'bat', 'cmd']:
        try:
            with open(file.filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            content = '无法读取文件内容'
    
    return render_template('new_preview.html', file=file, content=content)

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
def edit_file(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_authenticated or (file.owner_id != current_user.id and not current_user.is_admin):
        flash('您没有权限编辑此文件', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        content = request.form['content']
        with open(file.filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        flash('文件编辑成功', 'success')
        return redirect(url_for('preview_file', file_id=file.id))
    
    with open(file.filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    return render_template('new_edit.html', file=file, content=content)

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_authenticated or (file.owner_id != current_user.id and not current_user.is_admin):
        flash('您没有权限删除此文件', 'danger')
        return redirect(url_for('dashboard'))
    
    # 删除文件
    os.remove(file.filepath)
    # 从数据库中删除记录
    db.session.delete(file)
    db.session.commit()
    
    flash('文件删除成功', 'success')
    return redirect(request.referrer)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    if not keyword:
        return redirect(url_for('dashboard'))
    
    # 搜索文件名包含关键字的文件
    files = File.query.filter(File.filename.contains(keyword)).all()
    return render_template('new_search.html', files=files, keyword=keyword)

if __name__ == '__main__':
    from datetime import datetime
    with app.app_context():
        db.create_all()
        # 创建管理员账户
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@example.com', is_admin=True)
            admin_user.password = sha256_crypt.hash('admin123')
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True, port=5001)
