@app.route('/reset_db', methods=['POST'])
def reset_db():
    # Deletar o banco de dados
    db.drop_all()
    # Criar um novo banco de dados
    db.create_all()
    flash("Banco de dados foi resetado com sucesso!")
    return redirect(url_for('home'))  # Redireciona para a página inicial
