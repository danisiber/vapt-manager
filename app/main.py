from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import engine, get_db, Base
from app.models import user, project, target, finding
from app.routers import auth, projects, targets, findings, reports, users

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VAPT Manager — Bank Kalbar", version="1.0.0")

# Include routers
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(targets.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(users.router)

# Static + Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Pages
@app.get("/", response_class=RedirectResponse)
def root():
    return "/login"

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    return templates.TemplateResponse("projects.html", {"request": request})

@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int):
    return templates.TemplateResponse("project_detail.html", {"request": request, "project_id": project_id})

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    return templates.TemplateResponse("users.html", {"request": request})

# Seed admin on startup
@app.on_event("startup")
def seed_admin():
    db = next(get_db())
    from app.models.user import User, UserRole
    from app.utils.security import hash_password
    if not db.query(User).filter(User.username == "admin").first():
        admin = User(
            username="admin",
            email="admin@bankkalbar.co.id",
            hashed_password=hash_password("admin123"),
            role=UserRole.ADMIN
        )
        db.add(admin)
        db.commit()
