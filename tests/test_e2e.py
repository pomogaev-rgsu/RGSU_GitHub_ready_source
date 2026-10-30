"""Functional scenarios T01–T15 from table 15 of the thesis, plus security checks.
Results are automatically produced by running pytest. Only actually executed cases count as passed.
"""
import io
import re
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import main as m

@pytest.fixture(autouse=True)
def fresh_database():
    m.Base.metadata.drop_all(m.engine)
    m.Base.metadata.create_all(m.engine)
    m.seed_demo()
    yield

@pytest.fixture
def client():
    with TestClient(m.app,base_url='http://testserver') as c: yield c

def csrf(c,path='/login'):
    r=c.get(path)
    assert r.status_code==200, r.text[:200]
    return re.search(r'name="csrf_token" value="([^"]+)"',r.text).group(1)

def sign_in(c,email='student@demo.local',password='Demo2026!'):
    token=csrf(c)
    r=c.post('/login',data={'email':email,'password':password,'csrf_token':token},follow_redirects=False)
    return r

def post_csrf(c,path,data,form_page=None):
    # Session's CSRF cookie contains the signed token. We use a fresh GET to obtain form value.
    form_page=form_page or path
    token=csrf(c,form_page)
    return c.post(path,data={**data,'csrf_token':token},follow_redirects=False)

def seed_id(code):
    with m.SessionLocal() as db: return db.scalar(select(m.Application.id).where(m.Application.code==code))

def change(c,aid,status,comment=''):
    return post_csrf(c,f'/applications/{aid}/status',{'status':status,'comment':comment},f'/applications/{aid}')

def test_T01_authorization_with_correct_credentials(client):
    r=sign_in(client)
    assert r.status_code==303
    assert 'Мои последние заявки' in client.get('/dashboard').text

def test_T02_invalid_credentials(client):
    assert sign_in(client,password='not-the-password').status_code==200
    assert 'Неверный логин или пароль' in client.get('/login').text or 'Мои последние заявки' not in client.get('/dashboard').text

def test_T03_create_application_with_unique_number(client):
    sign_in(client)
    key=str(uuid.uuid4());r=post_csrf(client,'/applications/new',{'document_type':'study','purpose':'По месту требования','delivery':'digital','request_key':key})
    assert r.status_code==303
    assert r.headers['location'].startswith('/applications/')
    with m.SessionLocal() as db:
        a=db.scalar(select(m.Application).where(m.Application.request_key==key))
        assert a and a.code.startswith('REQ-') and a.status=='submitted'

def test_T04_validate_mandatory_fields(client):
    sign_in(client)
    r=post_csrf(client,'/applications/new',{'document_type':'','purpose':'По месту требования','delivery':'digital','request_key':str(uuid.uuid4())})
    assert r.status_code==200
    assert 'Проверьте обязательные поля' in r.text

def test_T05_view_only_own_applications(client):
    sign_in(client)
    text=client.get('/applications').text
    assert 'REQ-2026-001' in text and 'REQ-2026-004' not in text

def test_T06_allowed_status_change_and_history(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-003')
    r=change(client,aid,'review','Проверка начата')
    assert r.status_code==303
    with m.SessionLocal() as db:
        a=db.get(m.Application,aid)
        history=db.scalars(select(m.StatusHistory).where(m.StatusHistory.application_id==aid)).all()
        assert a.status=='review' and len(history)==2

def test_T07_invalid_status_transition_blocked(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-003')
    r=change(client,aid,'issued')
    assert r.status_code==400
    with m.SessionLocal() as db: assert db.get(m.Application,aid).status=='submitted'

def test_T08_clarification_creates_notification(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-002')
    r=change(client,aid,'clarification','Уточните год начала обучения')
    assert r.status_code==303
    with m.SessionLocal() as db:
        a=db.get(m.Application,aid)
        n=db.scalar(select(m.Notification).where(m.Notification.application_id==aid).order_by(m.Notification.id.desc()))
        assert a.status=='clarification' and 'Уточните год' in n.message

def test_T09_generate_study_pdf_with_cyrillic(client):
    sign_in(client)
    aid=seed_id('REQ-2026-001')
    r=client.get(f'/applications/{aid}/pdf')
    assert r.status_code==200 and r.headers['content-type']=='application/pdf'
    assert r.content.startswith(b'%PDF') and len(r.content)>3000
    import fitz
    text=' '.join(page.get_text() for page in fitz.open(stream=r.content,filetype='pdf'))
    assert 'Александра Морозова' in text and 'СПРАВКА С МЕСТА' in text and 'ДЕМОНСТРАЦИОННЫЙ' in text

def test_T10_generate_order_extract_pdf(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-003')
    r=client.get(f'/applications/{aid}/pdf')
    assert r.status_code==200 and r.content.startswith(b'%PDF')
    import fitz
    text=' '.join(page.get_text() for page in fitz.open(stream=r.content,filetype='pdf'))
    assert 'ВЫПИСКА ИЗ ПРИКАЗА' in text and '157/К-СТ' in text and '26.08.2024' in text

def test_T11_issued_at_is_saved(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-001')
    assert change(client,aid,'issued').status_code==303
    with m.SessionLocal() as db:
        a=db.get(m.Application,aid)
        assert a.status=='issued' and a.issued_at is not None

def test_T12_student_cannot_access_other_pdf(client):
    sign_in(client)
    aid=seed_id('REQ-2026-005')
    assert client.get(f'/applications/{aid}/pdf').status_code==403
    assert client.get(f'/applications/{aid}').status_code==403

def test_T13_administrator_changes_user_role(client):
    sign_in(client,'admin@demo.local')
    with m.SessionLocal() as db: target=db.scalar(select(m.User).where(m.User.email=='student2@demo.local'))
    assert post_csrf(client,'/admin/role',{'target_id':target.id,'role':'employee'},'/admin').status_code==303
    with m.SessionLocal() as db: assert db.get(m.User,target.id).role=='employee'

def test_T14_idempotent_repeat_submission(client):
    sign_in(client)
    key=str(uuid.uuid4())
    data={'document_type':'study','purpose':'По месту требования','delivery':'digital','request_key':key}
    first=post_csrf(client,'/applications/new',data)
    second=post_csrf(client,'/applications/new',data)
    assert first.status_code==303 and second.status_code==303
    assert first.headers['location'].split('?')[0]==second.headers['location'].split('?')[0]
    with m.SessionLocal() as db: assert db.scalar(select(func.count(m.Application.id)).where(m.Application.request_key==key))==1

def test_T15_notification_when_document_ready(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-002')
    assert change(client,aid,'preparation').status_code==303
    assert change(client,aid,'signing').status_code==303
    assert change(client,aid,'ready').status_code==303
    with m.SessionLocal() as db:
        n=db.scalar(select(m.Notification).where(m.Notification.application_id==aid).order_by(m.Notification.id.desc()))
        assert n and 'Готова к выдаче' in n.message

def test_security_csrf_rejects_missing_token(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-003')
    assert client.post(f'/applications/{aid}/status',data={'status':'issued'}).status_code==422

def test_security_student_cannot_change_status(client):
    sign_in(client)
    aid=seed_id('REQ-2026-003')
    assert change(client,aid,'review').status_code==403

def test_pdf_not_available_for_in_progress_student_application(client):
    sign_in(client)
    aid=seed_id('REQ-2026-002')
    assert client.get(f'/applications/{aid}/pdf').status_code==403


def test_T16_period_pdf_contains_demo_learning_results(client):
    sign_in(client,'employee@demo.local')
    aid=seed_id('REQ-2026-002')
    r=client.get(f'/applications/{aid}/pdf')
    assert r.status_code==200
    import fitz
    text=' '.join(page.get_text() for page in fitz.open(stream=r.content,filetype='pdf'))
    assert 'Математический анализ' in text and 'Базы данных' in text and '180' in text
