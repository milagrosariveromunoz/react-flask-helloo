
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import jwt_required

api = Blueprint('api', __name__)

@api.route('/user', methods=['POST'])
def add_new_user():

    body = request.json
    user_password = body.get("password")

    # Validar campos incompletos
    if not body.get("name"):
        return jsonify({"msg": "Introduzca nombre"}), 401
    if not body.get("email"):
        return jsonify({"msg": "Introduzca un correo"}), 401
    if not user_password:
        return jsonify({"msg": "Introduzca una contraseña"}), 401

    # Comprobar si el correo o el nombre ya están registrados
    if User.query.filter_by(name=body["name"]).first() is not None:
        return jsonify({"msg": "El nombre ya está registrado"}), 401
    if User.query.filter_by(email=body["email"]).first() is not None:
        return jsonify({"msg": "El correo ya está registrado"}), 401

    # Hashear contraseña y agregar usuario a la base de datos
    hashed_password = current_app.bcrypt.generate_password_hash(user_password).decode('utf-8')
    user = User(name=body["name"], email=body["email"], password=hashed_password)
    db.session.add(user)
    db.session.commit()

    response_body = {
        "msg": "Usuario creado"
    }

    return jsonify(response_body), 200


@api.route('/user', methods=['DELETE'])
def delete_user():
    body = request.json
    user_name = body.get("name")

    # Buscar y eliminar usuario de la base de datos
    user = User.query.filter_by(name=user_name).first()
    if user is None:
        return jsonify({"msg": "Usuario no encontrado"}), 401
    db.session.delete(user)
    db.session.commit()

    response_body = {
        "msg": "Usuario eliminado"
    }

    return jsonify(response_body), 200


@api.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    # Validar campos incompletos
    if not email:
        return jsonify({"msg": "Introduzca un correo"}), 401
    if not password:
        return jsonify({"msg": "Introduzca una contraseña"}), 401

    # Buscar usuario en la base de datos
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User.query.filter_by(name=email).first()
        if user is None:
            return jsonify({"msg": "Usuario no encontrado"}), 401

    # Verificar contraseña
    if not current_app.bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Contraseña incorrecta"}), 401

    # Generar token de acceso y enviar respuesta
    access_token = {
        "token": create_access_token(identity=email),
        "name": user.name
    }
    return jsonify(access_token=access_token), 200


@api.route("/profile", methods=["GET"])
@jwt_required()
def protected():
    # Acceder a la identidad del usuario actual
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
# Inicializa la extensión Flask-JWT-Extended
    jwt = JWTManager(app)

    # Inicializa la base de datos
    db.init_app(app)

    # Crea todas las tablas definidas en los modelos
    with app.app_context():
        db.create_all()

    # Agrega los endpoints al objeto app
    app.register_blueprint(api)

    # Ejecuta la aplicación
    app.run()

if __name__ == "__main__":
    app = Flask(__name__)
    app.config.from_object("api.config.Config")

