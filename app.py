from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import openai
from PyPDF2 import PdfReader
from fpdf import FPDF
from sqlalchemy import inspect
from unidecode import unidecode
import re

openai.api_key = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(os.path.dirname(__file__), "instance", "database.db")}'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Resume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    adapted_content = db.Column(db.Text)  # A coluna deve estar aqui
    adapted_filename = db.Column(db.Text)
    
    
with app.app_context():
    db.create_all()  # Cria as tabelas novamente
    
    inspector = inspect(db.engine)
    print("Tabelas criadas:", inspector.get_table_names())
    

    # Definindo uma pasta para salvar os arquivos
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Redireciona para a página de login ao acessar a raiz do site
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Atualizar o método de hash para 'pbkdf2:sha256'
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registro realizado com sucesso! Faça login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Falha no login. Verifique seu nome de usuário e senha.')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        file = request.files['file']
        resume_name = request.form['name']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Salvar detalhes do currículo no banco
            new_resume = Resume(name=resume_name, filename=filename, user_id=current_user.id)
            db.session.add(new_resume)
            db.session.commit()
            flash('Currículo enviado com sucesso!')
            return redirect(url_for('dashboard'))
        else:
            flash('Formato de arquivo inválido. Envie um PDF.')

    # Obtém todos os currículos carregados pelo usuário logado
    resumes = Resume.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', resumes=resumes)

@app.route('/download_resume/<int:resume_id>')
@login_required
def download_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    if resume.user_id != current_user.id:
        flash("Você não tem permissão para acessar este currículo.")
        return redirect(url_for('dashboard'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], resume.filename, as_attachment=True)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload_resume', methods=['GET', 'POST'])
@login_required
def upload_resume():
    if request.method == 'POST':
        file = request.files['file']
        resume_name = request.form['name']
        
        if file and allowed_file(file.filename):
            # Garantir que o nome do arquivo é seguro
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Salvar os detalhes no banco de dados
            new_resume = Resume(name=resume_name, filename=filename, user_id=current_user.id)
            db.session.add(new_resume)
            db.session.commit()
            flash('Currículo enviado com sucesso!')
            return redirect(url_for('dashboard'))
        else:
            flash('Formato de arquivo inválido. Envie um PDF.')
    return render_template('upload_resume.html')

@app.route('/edit_resume/<int:resume_id>', methods=['GET', 'POST'])
@login_required
def edit_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    if resume.user_id != current_user.id:
        flash("Você não tem permissão para editar este currículo.")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        new_name = request.form['name']
        resume.name = new_name
        db.session.commit()
        flash("Nome do currículo atualizado com sucesso!")
        return redirect(url_for('dashboard'))
    
    return render_template('edit_resume.html', resume=resume)

@app.route('/delete_resume/<int:resume_id>', methods=['POST'])
@login_required
def delete_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    if resume.user_id != current_user.id:
        flash("Você não tem permissão para excluir este currículo.")
        return redirect(url_for('dashboard'))
    
    # Remove o arquivo do sistema
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Remove o registro do banco de dados
    db.session.delete(resume)
    db.session.commit()
    flash("Currículo excluído com sucesso!")
    return redirect(url_for('dashboard'))

def extract_all_sections(pdf_path):
    # Extracts various sections like Summary, Experience, Education, Languages, and Skills dynamically
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    # Dynamically find key sections and extract content (adjust patterns based on general resume structure)
    sections = {
        "Summary": "",
        "Professional Experience": "",
        "Education": "",
        "Languages": "",
        "Skills": ""
    }
    
    # Regex patterns can be tailored to capture the sections better, if needed
    for section in sections.keys():
        start_idx = text.lower().find(section.lower())
        next_section_idx = min(
            [text.lower().find(sec.lower(), start_idx + 1) for sec in sections.keys() if text.lower().find(sec.lower(), start_idx + 1) > -1] + [len(text)]
        )
        if start_idx != -1:
            sections[section] = text[start_idx:next_section_idx].strip()

    return sections

def extract_personal_info(text):
    # Regex para capturar o nome e informações pessoais
    name_pattern = r"^(.*)$"  # Captura tudo da primeira linha
    email_pattern = r"([\w\.-]+@[\w\.-]+)"
    phone_pattern = r"(\+?\d{2}\s*\(?\d{2}\)?\s*\d{4,5}-?\d{4})"
    linkedin_pattern = r"(https?://[^\s]+)"
    address_pattern = r"([A-Za-z\s]+,\s*[A-Za-z\s]+-\s*[A-Z]{2})"


    name = re.search(name_pattern, text, re.MULTILINE)
    email = re.search(email_pattern, text)
    phone = re.search(phone_pattern, text)
    linkedin = re.search(linkedin_pattern, text)
    address = re.search(address_pattern, text)

    return {
        "name": name.group(1).strip() if name else "Nome não encontrado",
        "email": email.group(0) if email else "Email não encontrado",
        "phone": phone.group(0) if phone else "Telefone não encontrado",
        "linkedin": linkedin.group(0) if linkedin else "LinkedIn não encontrado",
        "address": address.group(0) if address else "Endereço não encontrado"
    }

def add_section(pdf, title, content, title_font_size=13, content_font_size=11, is_bold=False, bullet=False):
    # Add the title with underline for section headers
    pdf.set_font("Arial", "B" if is_bold else "", size=title_font_size)
    pdf.cell(0, 10, unidecode(title), ln=True, border="B")  # Underlined title
    pdf.ln(5)  # Space after the title
    
    # Set font for content
    pdf.set_font("Arial", "", size=content_font_size)
    
    # Loop through each line in the content and add bullets if needed
    for line in content.splitlines():
            pdf.cell(0, 10, unidecode(line), ln=True)
    pdf.ln(8)  # Add space after each section to match template spacing


@app.route('/adapt_resume/<int:resume_id>', methods=['GET', 'POST'])
@login_required
def adapt_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    if resume.user_id != current_user.id:
        flash("Você não tem permissão para adaptar este currículo.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        job_description = request.form['job_description']
        
        # Extrai as seções do currículo original
        sections = extract_all_sections(os.path.join(app.config['UPLOAD_FOLDER'], resume.filename))
        
        pdf_text = ""
        with open(os.path.join(app.config['UPLOAD_FOLDER'], resume.filename), 'rb') as file:
            reader = PdfReader(file)
            for page in reader.pages:
                pdf_text += page.extract_text()  # Coleta todo o texto

        personal_info = extract_personal_info(pdf_text)

        # Prompt para o ChatGPT
        prompt_script = (
            f"I need you to tailorize my recent experience to a vacancy I want to apply for. You are allowed to change the order of the experiences to have the most relevant first, "
            f"remove items that don't add to the role and add experiences that are already there. Let me know what is missing and what you have removed (if you did). "
            f"Keep in mind that for my current role the bullets need to start with present continuous, and the past ones with past perfect. "
            f"Please dont write any comments or anything else, just the sections of the tailored resume."
            f"Use the other sections provided below and integrate them into the adapted resume.\n\n"
            f"---\n\n"
            f"{personal_info['name']} | {personal_info['email']}\n{personal_info['linkedin']} | {personal_info['address']}\n"
            f"Summary\n{sections['Summary']}\n\n"
            f"Professional Experience\n{sections['Professional Experience']}\n\n"
            f"Job Description\n{job_description}\n\n"
            f"Education\n{sections['Education']}\n\n"
            f"Languages\n{sections['Languages']}\n\n"
            f"Skills\n{sections['Skills']}"
        )

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are a resume adaptation assistant."},
                      {"role": "user", "content": prompt_script}],
            max_tokens=1500,
            temperature=0.7,
        )

        adapted_content = response.choices[0].message['content']

        # Salvar o conteúdo adaptado na sessão
        session['adapted_resume_text'] = adapted_content
        
        # Criação do PDF com formatação por seção
        adapted_filename = f"adapted_resume_{resume.id}_{current_user.id}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], adapted_filename)

# Create PDF with formatted sections as per template
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

# Add Personal Info Section with specific styling
        pdf.set_font("Arial", "B", size=14)
        pdf.cell(0, 10, unidecode(personal_info['name']), ln=True)  # Name in bold, larger font
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, "Carreira", ln=True)  # Sub-heading
        pdf.cell(0, 8, unidecode(f"{personal_info['email']} | {personal_info['phone']} | {personal_info['linkedin']}"), ln=True)
        pdf.cell(0, 8, unidecode(f" Brazil | {personal_info['address']}"), ln=True)
        pdf.ln(10)  # Space after header

# Add sections with exact font size, spacing, and bullets
        add_section(pdf, "SUMMARY", sections["Summary"], title_font_size=13, content_font_size=11, is_bold=True)
        add_section(pdf, "PROFESSIONAL EXPERIENCE", adapted_content, title_font_size=13, content_font_size=11, is_bold=True)
        add_section(pdf, "EDUCATION", sections["Education"], title_font_size=13, content_font_size=11, is_bold=True)
        add_section(pdf, "LANGUAGES", sections["Languages"], title_font_size=13, content_font_size=11, is_bold=True)
        add_section(pdf, "SKILLS", sections["Skills"], title_font_size=13, content_font_size=11, is_bold=True)

# Save the final PDF
        pdf.output(pdf_path)



        # Armazena no banco de dados
        resume.adapted_content = adapted_content
        resume.adapted_filename = adapted_filename
        db.session.commit()

        return render_template('preview_resume.html', adapted_resume=adapted_content, resume=resume)

    return render_template('adapt_resume.html', resume=resume)


@app.route('/download_adapted_resume/<int:resume_id>', methods=['POST'])
@login_required
def download_adapted_resume(resume_id):
    adapted_resume_text = session.get('adapted_resume_text')
    if not adapted_resume_text:
        flash("No adapted resume found.")
        return redirect(url_for('dashboard'))

    # Cria um PDF com o conteúdo adaptado
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    # Para lidar com caracteres UTF-8, converta o texto para ASCII
    adapted_resume_text = adapted_resume_text.encode('latin-1', 'replace').decode('latin-1')

    # Adiciona o texto ao PDF
    pdf.multi_cell(0, 10, adapted_resume_text)

    # Salva o PDF temporariamente e envia para download
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f"adapted_resume_{resume_id}.pdf")
    pdf.output(pdf_path)

    return send_from_directory(app.config['UPLOAD_FOLDER'], f"adapted_resume_{resume_id}.pdf", as_attachment=True)

@app.route('/download_adapted_resume_dashboard/<int:resume_id>', methods=['GET'])
@login_required
def download_adapted_resume_dashboard(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Verifica se o currículo adaptado foi gerado
    if not resume.adapted_filename:
        flash("Não há currículo adaptado disponível para download.")
        return redirect(url_for('dashboard'))

    # Caminho do arquivo adaptado
    adapted_resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume.adapted_filename)

    # Verifica se o arquivo existe
    if not os.path.exists(adapted_resume_path):
        flash("Arquivo adaptado não encontrado.")
        return redirect(url_for('dashboard'))

    adapted_content = resume.adapted_content  # Obtenha o conteúdo adaptado diretamente do banco de dados

    # Criação do PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    # Para lidar com caracteres UTF-8, converta o texto para ASCII
    adapted_content = adapted_content.encode('latin-1', 'replace').decode('latin-1')

    # Adiciona o texto ao PDF
    pdf.multi_cell(0, 10, adapted_content)

    # Salva o PDF
    pdf.output(adapted_resume_path)

    return send_from_directory(app.config['UPLOAD_FOLDER'], resume.adapted_filename, as_attachment=True)

@app.route('/view_resumes', methods=['GET'])
@login_required
def view_resumes():
    resumes = Resume.query.filter_by(user_id=current_user.id).all()
    return render_template('view_resumes.html', resumes=resumes)


if __name__ == '__main__':
    app.run(debug=True)
