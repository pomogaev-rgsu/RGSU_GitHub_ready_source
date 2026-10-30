"""Educational reference-app for student document requests, implemented with FastAPI.
Do not use with real student data without security review and legal authorization.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware

ROOT = Path(__file__).resolve().parent
DB_PATH = os.environ.get('APP_DB_PATH', str(ROOT / 'demo.db'))
DATABASE_URL = os.environ.get('DATABASE_URL', f'sqlite:///{DB_PATH}')
SECRET_KEY = os.environ.get('APP_SECRET_KEY') or secrets.token_urlsafe(48)
engine_kwargs = {'connect_args': {'check_same_thread': False}} if DATABASE_URL.startswith('sqlite:') else {}
engine = create_engine(DATABASE_URL, future=True, **engine_kwargs)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
signer = URLSafeTimedSerializer(SECRET_KEY, salt='rgsu-educational-session')

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(150))
    password_hash: Mapped[str] = mapped_column(String(220))
    role: Mapped[str] = mapped_column(String(30), default='student')
    student_id: Mapped[str | None] = mapped_column(String(24), nullable=True)
    faculty: Mapped[str | None] = mapped_column(String(180), nullable=True)
    program: Mapped[str | None] = mapped_column(String(180), nullable=True)
    course: Mapped[int | None] = mapped_column(Integer, nullable=True)
    form_of_study: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

class EducationOrder(Base):
    __tablename__ = 'education_orders'
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    order_number: Mapped[str] = mapped_column(String(40))
    order_date: Mapped[str] = mapped_column(String(20))
    order_kind: Mapped[str] = mapped_column(String(100))
    decision: Mapped[str] = mapped_column(Text)

class LearningResult(Base):
    __tablename__ = 'learning_results'
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    discipline: Mapped[str] = mapped_column(String(180))
    hours: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(50))
    semester: Mapped[int] = mapped_column(Integer)

class Application(Base):
    __tablename__ = 'applications'
    __table_args__ = (UniqueConstraint('student_id', 'request_key', name='uq_student_request'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    order_id: Mapped[int | None] = mapped_column(ForeignKey('education_orders.id'), nullable=True)
    request_key: Mapped[str] = mapped_column(String(42))
    document_type: Mapped[str] = mapped_column(String(30))
    purpose: Mapped[str] = mapped_column(String(150), default='По месту требования')
    delivery: Mapped[str] = mapped_column(String(30), default='digital')
    comment: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(30), default='submitted')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    issued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    student: Mapped[User] = relationship(foreign_keys=[student_id])
    assigned_to: Mapped[User | None] = relationship(foreign_keys=[assigned_to_id])
    order: Mapped[EducationOrder | None] = relationship(foreign_keys=[order_id])

class StatusHistory(Base):
    __tablename__ = 'status_history'
    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey('applications.id'))
    previous: Mapped[str] = mapped_column(String(30), default='')
    current: Mapped[str] = mapped_column(String(30))
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    comment: Mapped[str] = mapped_column(Text, default='')
    at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Notification(Base):
    __tablename__ = 'notifications'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    application_id: Mapped[int | None] = mapped_column(ForeignKey('applications.id'), nullable=True)
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(Text)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = 'audit_log'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default='')
    at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

DOCS = {'study': 'Справка с места учёбы', 'period': 'Справка о периоде обучения', 'order': 'Выписка из приказа'}
STATUSES = {'submitted': 'Подана', 'review': 'На проверке', 'clarification': 'Требует уточнения', 'preparation': 'В оформлении', 'signing': 'На подписании', 'ready': 'Готова к выдаче', 'issued': 'Выдана', 'rejected': 'Отклонена'}
ALLOWED = {
    'submitted': {'review','rejected'}, 'review': {'clarification','preparation','rejected'},
    'clarification': {'review'}, 'preparation': {'signing','clarification'},
    'signing': {'ready','preparation'}, 'ready': {'issued'}, 'issued': set(), 'rejected': set()
}
ROLES = {'student': 'Обучающийся', 'employee': 'Сотрудник', 'admin': 'Администратор'}

def pass_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + '$' + hashed.hex()

def pass_verify(password: str, encoded: str) -> bool:
    try:
        salt, digest = encoded.split('$', 1)
        found = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(found, bytes.fromhex(digest))
    except (ValueError, TypeError): return False

def database_session():
    with SessionLocal() as session: yield session

DB = Annotated[Session, Depends(database_session)]


def get_user(request: Request, db: Session) -> User | None:
    token = request.cookies.get('rgsu_session')
    if not token: return None
    try: payload = signer.loads(token, max_age=60*60*8)
    except (BadSignature, SignatureExpired): return None
    user = db.get(User, payload.get('uid'))
    return user if user and user.is_active else None


def require_user(request: Request, db: DB) -> User:
    user = get_user(request, db)
    if user is None: raise HTTPException(303, headers={'Location': '/login'})
    return user

CURRENT = Annotated[User, Depends(require_user)]

def require_roles(user: User, *roles: str):
    if user.role not in roles: raise HTTPException(403, 'Недостаточно полномочий')


def csrf_cookie(request: Request):
    try:
        token = signer.loads(request.cookies.get('rgsu_csrf', ''), max_age=60*60*24)
        if isinstance(token, str) and len(token)>20: return token
    except (BadSignature,SignatureExpired): pass
    return secrets.token_urlsafe(24)

def verify_csrf(request: Request, token: str):
    try: expected = signer.loads(request.cookies.get('rgsu_csrf',''), max_age=60*60*24)
    except (BadSignature,SignatureExpired): raise HTTPException(403, 'CSRF-токен отсутствует')
    if not hmac.compare_digest(str(expected), token): raise HTTPException(403, 'Неверный CSRF-токен')

app = FastAPI(title='РГСУ · Учебный сервис справок', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
templates = Jinja2Templates(directory=ROOT / 'templates')
templates.env.globals.update(docs=DOCS, statuses=STATUSES, roles=ROLES)

def page(request: Request, name: str, **ctx):
    token = csrf_cookie(request)
    resp = templates.TemplateResponse(request, name, {'csrf_token': token, 'now': datetime.now(), **ctx})
    resp.set_cookie('rgsu_csrf', signer.dumps(token), httponly=True, samesite='lax')
    return resp


def redirect(location, request=None):
    return RedirectResponse(location, status_code=303)

def log(db, user_id, action, detail): db.add(AuditLog(user_id=user_id,action=action,detail=detail))

def add_note(db, user_id, application_id, title, message):
    db.add(Notification(user_id=user_id,application_id=application_id,title=title,message=message))


def seed_demo(force=False):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.scalar(select(func.count(User.id))) and not force: return
        people = [
            User(email='student@demo.local', full_name='Александра Морозова', password_hash=pass_hash('Demo2026!'), role='student', student_id='2026-0815', faculty='Факультет информационных технологий', program='Информационные системы и технологии', course=3, form_of_study='Очная'),
            User(email='employee@demo.local', full_name='Екатерина Смирнова', password_hash=pass_hash('Demo2026!'), role='employee'),
            User(email='admin@demo.local', full_name='Ирина Волкова', password_hash=pass_hash('Demo2026!'), role='admin'),
            User(email='student2@demo.local', full_name='Дмитрий Орлов', password_hash=pass_hash('Demo2026!'), role='student', student_id='2025-0631', faculty='Факультет экономики', program='Экономика', course=2, form_of_study='Заочная'),
        ]
        db.add_all(people); db.flush()
        demo_orders=[
            EducationOrder(student_id=people[0].id,order_number='157/К-СТ',order_date='26.08.2024',order_kind='О зачислении',decision='Зачислить Александру Морозову на образовательную программу «Информационные системы и технологии».'),
            EducationOrder(student_id=people[0].id,order_number='048/УЧ',order_date='03.09.2025',order_kind='О переводе на следующий курс',decision='Перевести Александру Морозову на третий курс обучения.'),
            EducationOrder(student_id=people[3].id,order_number='114/К-СТ',order_date='24.08.2025',order_kind='О зачислении',decision='Зачислить Дмитрия Орлова на образовательную программу «Экономика».'),
        ]
        db.add_all(demo_orders); db.flush()
        db.add_all([
            LearningResult(student_id=people[0].id,discipline='Информатика',hours=144,grade='Отлично',semester=1),
            LearningResult(student_id=people[0].id,discipline='Математический анализ',hours=180,grade='Хорошо',semester=1),
            LearningResult(student_id=people[0].id,discipline='Базы данных',hours=108,grade='Отлично',semester=3),
            LearningResult(student_id=people[0].id,discipline='Проектирование информационных систем',hours=144,grade='Отлично',semester=4),
            LearningResult(student_id=people[3].id,discipline='Микроэкономика',hours=108,grade='Хорошо',semester=2),
            LearningResult(student_id=people[3].id,discipline='Статистика',hours=108,grade='Зачтено',semester=2),
        ])
        rows=[
            ('REQ-2026-001','study','Для предоставления работодателю','ready','digital',people[0],''),
            ('REQ-2026-002','period','Для перевода в другую организацию','review','digital',people[0],'Необходим период за 2024–2026 гг.'),
            ('REQ-2026-003','order','По месту требования','submitted','paper',people[0],'Выписка из приказа о зачислении'),
            ('REQ-2026-004','study','Для военкомата','preparation','paper',people[3],''),
            ('REQ-2026-005','study','Для социальной поддержки','issued','digital',people[3],''),
            ('REQ-2026-006','period','Для предоставления в другую организацию','clarification','digital',people[3],'Уточнить период обучения'),
        ]
        for code,typ,purpose,status,delivery,student,comment in rows:
            obj=Application(code=code,request_key=str(uuid.uuid4()),student_id=student.id,assigned_to_id=people[1].id,order_id=demo_orders[0].id if typ=='order' else None,document_type=typ,purpose=purpose,status=status,delivery=delivery,comment=comment,issued_at=datetime.now(timezone.utc) if status=='issued' else None)
            db.add(obj); db.flush(); db.add(StatusHistory(application_id=obj.id,current=status,actor_id=people[1].id if status!='submitted' else student.id))
        add_note(db,people[0].id,1,'Справка готова к выдаче','Документ по заявке REQ-2026-001 подготовлен и доступен для просмотра.')
        add_note(db,people[0].id,2,'Заявка на проверке','Сотрудник приступил к рассмотрению обращения REQ-2026-002.')
        log(db,people[2].id,'demo_seed','Тестовые записи созданы автоматически')
        db.commit()

seed_demo()

@app.get('/', response_class=HTMLResponse)
def home(request: Request, db: DB):
    user=get_user(request,db)
    return redirect('/dashboard' if user else '/login')

@app.get('/login', response_class=HTMLResponse)
def login_get(request: Request, db: DB):
    if get_user(request,db): return redirect('/dashboard')
    return page(request,'login.html', error=None)

@app.post('/login')
def login_post(request: Request, db: DB, email: str=Form(...), password: str=Form(...), csrf_token: str=Form(...)):
    verify_csrf(request,csrf_token)
    user=db.scalar(select(User).where(User.email==email.lower().strip()))
    if not user or not user.is_active or not pass_verify(password,user.password_hash):
        return page(request,'login.html',error='Неверный логин или пароль')
    log(db,user.id,'login','Вход в демонстрационную систему'); db.commit()
    resp=redirect('/dashboard')
    resp.set_cookie('rgsu_session',signer.dumps({'uid': user.id}), httponly=True,samesite='lax',max_age=60*60*8)
    return resp

@app.post('/logout')
def logout(request: Request, csrf_token:str=Form(...)):
    verify_csrf(request,csrf_token)
    resp=redirect('/login'); resp.delete_cookie('rgsu_session'); return resp

@app.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request, db: DB, user: CURRENT):
    if user.role=='student':
        apps=db.scalars(select(Application).where(Application.student_id==user.id).order_by(Application.id.desc())).all()
        notes=db.scalars(select(Notification).where(Notification.user_id==user.id).order_by(Notification.id.desc()).limit(4)).all()
    else:
        apps=db.scalars(select(Application).order_by(Application.id.desc())).all()
        notes=[]
    return page(request,'dashboard.html',user=user,applications=apps,notifications=notes)

@app.get('/applications/new', response_class=HTMLResponse)
def new_get(request: Request, db: DB, user: CURRENT):
    require_roles(user,'student')
    orders=db.scalars(select(EducationOrder).where(EducationOrder.student_id==user.id)).all()
    return page(request,'new.html',user=user,orders=orders,request_key=str(uuid.uuid4()), error=None)

@app.post('/applications/new')
def new_post(request: Request, db: DB, user: CURRENT, document_type:str=Form(''), purpose:str=Form(''), delivery:str=Form(''), comment:str=Form(''), order_id:str=Form(''), request_key:str=Form(...), csrf_token:str=Form(...)):
    require_roles(user,'student'); verify_csrf(request,csrf_token)
    orders=db.scalars(select(EducationOrder).where(EducationOrder.student_id==user.id)).all()
    if document_type not in DOCS or delivery not in ('digital','paper') or not (1<=len(purpose)<=150):
        return page(request,'new.html',user=user,orders=orders,request_key=request_key,error='Проверьте обязательные поля')
    selected_order=None
    if document_type=='order':
        selected_order=next((o for o in orders if str(o.id)==order_id),None)
        if selected_order is None:
            return page(request,'new.html',user=user,orders=orders,request_key=request_key,error='Выберите приказ из доступного списка')
    try: uuid.UUID(request_key)
    except ValueError: raise HTTPException(400,'Неверный идентификатор операции')
    old=db.scalar(select(Application).where(Application.student_id==user.id,Application.request_key==request_key))
    if old: return redirect(f'/applications/{old.id}')
    code='REQ-'+str(datetime.now().year)+'-'+uuid.uuid4().hex[:6].upper()
    obj=Application(code=code, student_id=user.id, order_id=selected_order.id if selected_order else None, document_type=document_type, purpose=purpose, delivery=delivery, comment=comment[:1500], request_key=request_key)
    db.add(obj); db.flush()
    db.add(StatusHistory(application_id=obj.id,previous='',current='submitted',actor_id=user.id))
    log(db,user.id,'application_created',code)
    db.commit()
    return redirect(f'/applications/{obj.id}?created=1')

@app.get('/applications',response_class=HTMLResponse)
def apps_list(request: Request, db: DB, user: CURRENT, status:str=''):
    query=select(Application).order_by(Application.id.desc())
    if user.role=='student': query=query.where(Application.student_id==user.id)
    if status in STATUSES: query=query.where(Application.status==status)
    apps=db.scalars(query).all()
    return page(request,'applications.html',user=user,applications=apps,selected=status)


def accessible_application(db, user, application_id):
    application=db.get(Application,application_id)
    if application is None: raise HTTPException(404,'Обращение не найдено')
    if user.role=='student' and application.student_id!=user.id: raise HTTPException(403,'Нет доступа к чужой заявке')
    return application

@app.get('/applications/{application_id}',response_class=HTMLResponse)
def app_detail(request: Request, application_id:int, db: DB, user: CURRENT, created:int=0):
    a=accessible_application(db,user,application_id)
    history=db.scalars(select(StatusHistory).where(StatusHistory.application_id==a.id).order_by(StatusHistory.id.desc())).all()
    actors={u.id: u.full_name for u in db.scalars(select(User)).all()}
    allowed=sorted(ALLOWED[a.status])
    return page(request,'detail.html',user=user,a=a,history=history,actors=actors,allowed=allowed,created=created)

@app.post('/applications/{application_id}/status')
def change_status(request:Request, application_id:int,db:DB,user:CURRENT,status:str=Form(...),comment:str=Form(''),csrf_token:str=Form(...)):
    require_roles(user,'employee','admin'); verify_csrf(request,csrf_token)
    a=accessible_application(db,user,application_id)
    if status not in ALLOWED[a.status]: raise HTTPException(400,'Недопустимый переход статуса')
    if status=='issued' and a.status!='ready': raise HTTPException(400,'Документ не готов')
    prior=a.status; a.status=status; a.updated_at=datetime.now(timezone.utc)
    if status=='issued': a.issued_at=datetime.now(timezone.utc)
    if a.assigned_to_id is None: a.assigned_to_id=user.id
    db.add(StatusHistory(application_id=a.id,previous=prior,current=status,actor_id=user.id,comment=comment[:1500]))
    add_note(db,a.student_id,a.id,'Обновление заявки',f'{a.code}: статус изменён на «{STATUSES[status]}». '+comment[:160])
    log(db,user.id,'status_changed',f'{a.code}: {prior} → {status}')
    db.commit(); return redirect(f'/applications/{a.id}?updated=1')

@app.get('/notifications',response_class=HTMLResponse)
def notifications(request: Request, db:DB, user:CURRENT):
    items=db.scalars(select(Notification).where(Notification.user_id==user.id).order_by(Notification.id.desc())).all()
    return page(request,'notifications.html',user=user,notifications=items)

@app.get('/admin',response_class=HTMLResponse)
def admin_panel(request:Request,db:DB,user:CURRENT):
    require_roles(user,'admin')
    users=db.scalars(select(User).order_by(User.id)).all()
    logs=db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(12)).all()
    return page(request,'admin.html',user=user,users=users,logs=logs)

@app.post('/admin/role')
def admin_role(request:Request, db:DB,user:CURRENT,target_id:int=Form(...),role:str=Form(...),csrf_token:str=Form(...)):
    require_roles(user,'admin'); verify_csrf(request,csrf_token)
    target=db.get(User,target_id)
    if target is None or role not in ROLES: raise HTTPException(400,'Ошибка данных')
    if target.id==user.id and role!='admin': raise HTTPException(400,'Нельзя снять собственную роль администратора')
    before=target.role; target.role=role
    log(db,user.id,'role_updated',f'{target.email}: {before} → {role}')
    db.commit(); return redirect('/admin?updated=1')

# PDF generator emits a DRAFT sample using fictitious data; it is not an officially issued RGSU certificate.
FONTS = '/usr/share/fonts/truetype/dejavu'
LOCAL_FONTS = ROOT / 'assets' / 'fonts'
def find_font(env_name, default_names):
    locations=[os.environ.get(env_name,''),*[str(LOCAL_FONTS / f) for f in default_names],
               *[str(Path(FONTS) / f) for f in default_names],
               *[str(Path('C:/Windows/Fonts') / f) for f in ['arial.ttf' if env_name=='RGSU_FONT_REGULAR' else 'arialbd.ttf']]]
    for item in locations:
        if item and Path(item).exists(): return item
    raise RuntimeError(f'Не найден шрифт Unicode. Укажите путь в переменной {env_name}')
FONT_PATH = find_font('RGSU_FONT_REGULAR',['DejaVuSans.ttf'])
FONT_BOLD_PATH = find_font('RGSU_FONT_BOLD',['DejaVuSans-Bold.ttf'])
pdfmetrics.registerFont(TTFont('DejaVu', FONT_PATH))
pdfmetrics.registerFont(TTFont('DejaVu-Bold', FONT_BOLD_PATH))


def build_pdf(a: Application, learning_results: list[LearningResult] | None = None) -> bytes:
    result=io.BytesIO(); doc=SimpleDocTemplate(result,pagesize=A4,rightMargin=55,leftMargin=55,topMargin=60,bottomMargin=50,title=f'Демонстрационная справка {a.code}')
    headline=ParagraphStyle('h',fontName='DejaVu-Bold',fontSize=17,leading=25,alignment=TA_CENTER,textColor=colors.HexColor('#10294b'),spaceAfter=12)
    body=ParagraphStyle('b',fontName='DejaVu',fontSize=10.5,leading=20,textColor=colors.HexColor('#21344d'),spaceAfter=10)
    small=ParagraphStyle('s',fontName='DejaVu',fontSize=8.3,leading=15,textColor=colors.HexColor('#536780'))
    mid=ParagraphStyle('mid',parent=body,alignment=TA_CENTER)
    content=[Paragraph('РОССИЙСКИЙ ГОСУДАРСТВЕННЫЙ<br/>СОЦИАЛЬНЫЙ УНИВЕРСИТЕТ',ParagraphStyle('inst',parent=small,alignment=TA_CENTER)),Spacer(1,25),Paragraph(DOCS[a.document_type].upper(),headline),Paragraph('Учебный демонстрационный образец',mid),Spacer(1,13)]
    rows=[['Регистрационный номер',a.code],['Дата формирования',datetime.now().strftime('%d.%m.%Y')],['Обучающийся',a.student.full_name],['Факультет',a.student.faculty or 'Уточняется'],['Образовательная программа',a.student.program or 'Уточняется'],['Форма обучения',a.student.form_of_study or 'Уточняется'],['Курс',str(a.student.course or '—')],['Назначение',a.purpose]]
    table=Table([[Paragraph(str(left),small),Paragraph(str(right),body)] for left,right in rows],colWidths=[155,325],hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#eef3f9')),('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),11),('TOPPADDING',(0,0),(-1,-1),10),('LINEBELOW',(0,0),(-1,-2),0.4,colors.HexColor('#dce5ef'))]))
    content.extend([table,Spacer(1,25)])
    if a.document_type=='study':
        explain='Настоящий демонстрационный образец отражает сведения о прохождении обучения, внесённые в тестовую базу информационной системы.'
    elif a.document_type=='period':
        explain='Ниже приведены условные результаты освоения дисциплин из тестовой базы. Они не подтверждены официальными образовательными документами.'
    else:
        explain='Приведённые реквизиты приказа являются тестовыми. Оригинал распорядительного акта РГСУ не использовался.'
    content.append(Paragraph(explain,body))
    if a.document_type=='period':
        heading=ParagraphStyle('table_header',fontName='DejaVu-Bold',fontSize=8.2,leading=13,textColor=colors.HexColor('#184276'))
        cells=[[Paragraph('Дисциплина',heading),Paragraph('Семестр',heading),Paragraph('Часы',heading),Paragraph('Результат',heading)]]
        for rec in learning_results or []:
            cells.append([Paragraph(rec.discipline,small),Paragraph(str(rec.semester),small),Paragraph(str(rec.hours),small),Paragraph(rec.grade,small)])
        tbl=Table(cells,colWidths=[240,65,60,115],repeatRows=1)
        tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eaf1fc')),('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#dce5ef')),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
        content.extend([Spacer(1,12),tbl])
    elif a.document_type=='order' and a.order:
        content.extend([Spacer(1,10),Paragraph('Реквизиты выбранного приказа',ParagraphStyle('orderh',parent=body,fontName='DejaVu-Bold')),Paragraph(f'Номер: {a.order.order_number}; дата: {a.order.order_date}; вид: {a.order.order_kind}.',body),Paragraph(a.order.decision,body)])
    content.extend([Spacer(1,18),Paragraph('Документ сформирован автоматически на тестовых данных. Не содержит подписи уполномоченного лица, печати либо квалифицированной электронной подписи.',small)])
    def footer(canvas, document):
        w,h=A4
        canvas.saveState();canvas.setStrokeColor(colors.HexColor('#dce5ef'));canvas.line(55,47,w-55,47)
        canvas.setFont('DejaVu',7.5);canvas.setFillColor(colors.HexColor('#6b7c92'));canvas.drawString(55,32,'УЧЕБНЫЙ ПРОЕКТ  ·  НЕ ЯВЛЯЕТСЯ ОФИЦИАЛЬНЫМ ДОКУМЕНТОМ')
        canvas.setFont('DejaVu-Bold',29);canvas.setFillColor(colors.HexColor('#edf1f6'));canvas.saveState();canvas.translate(w/2,h/2);canvas.rotate(28);canvas.drawCentredString(0,0,'ДЕМОНСТРАЦИОННЫЙ ОБРАЗЕЦ');canvas.restoreState();canvas.restoreState()
    doc.build(content,onFirstPage=footer,onLaterPages=footer)
    return result.getvalue()

@app.get('/applications/{application_id}/pdf')
def download_pdf(request:Request,application_id:int,db:DB,user:CURRENT):
    a=accessible_application(db,user,application_id)
    if user.role=='student' and a.status not in ('ready','issued'): raise HTTPException(403,'Документ пока недоступен')
    learning_results=db.scalars(select(LearningResult).where(LearningResult.student_id==a.student_id).order_by(LearningResult.semester,LearningResult.id)).all() if a.document_type=='period' else []
    data=build_pdf(a,learning_results)
    return StreamingResponse(io.BytesIO(data),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="sample_{a.code}.pdf"','X-Content-Type-Options':'nosniff'})

@app.get('/health')
def health(): return {'status':'ok','mode':'educational_demo','database':'connected'}
