from flask import Flask, request, jsonify, make_response,redirect,url_for
from flask_migrate import Migrate
from flask_restful import Resource, Api, reqparse
from models import db, User,Department,Report,Collection
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token,unset_jwt_cookies
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth



app = Flask(__name__)

CORS(app,resources={r"/*": {"origins": ["http://localhost:5173","http://localhost:5174"],"supports_credentials": True,"methods": ["GET", "POST","PATCH", "PUT", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.json.compact = False

app.secret_key = 'secret key'
app.config['JWT_SECRET_KEY'] = "b'\x03\xa3\x8c\xb3\n\xf4}\x16aFh\xc5'"

db.init_app(app)

migrate = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)



class UserRegister(Resource):
    @cross_origin()
    def post(self):
        name = request.json['name']
        phone_number = request.json['phone_number']
        email = request.json['email']
        
        password = str(request.json['password'])
        

        user_exists = User.query.filter_by(email=email).first()

        if user_exists:
            return jsonify({'error': 'User already exists'}), 409
        

        hashed_pw = bcrypt.generate_password_hash(password)
       

        access_token = create_access_token(identity=email)

        new_user = User(
            name = name,
            phone_number = phone_number,
            email=email, 
             
            password=hashed_pw,
            
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "id": new_user.id,
            "email": new_user.email,
            "name": new_user.name,
            
            "access_token": access_token,
        }),201
        
class UserLogin(Resource):
    @cross_origin()
    def post(self):
        email = request.json['email']
        password = request.json['password']

        user = User.query.filter_by(email=email).first()

        if user is None:
            return jsonify({'error': 'Unauthorized'}), 401

        if not bcrypt.check_password_hash(user.password, password):
            return jsonify({'error': 'Unauthorized, incorrect password'}), 401
        
        access_token = create_access_token(identity=email)
        user.access_token = access_token


        return jsonify({
            "id": user.id,
            "email": user.email,
            "access_token": user.access_token
            
          
        })   
        
class Departments(Resource):
    def get(self):
       
            departments = [departments.to_dict(only=('id', 'name','description')) for departments in Department.query.all()]
            return make_response(jsonify(departments),200)
        
    def post(self):  
        data = request.json

        new_department = Department(
            name = data["name"],
            description = data["description"],
            
            
            
        )

        db.session.add(new_department)
        db.session.commit()

        return make_response(jsonify(new_department.to_dict(only=("id","name","description"))),200) 
    
class DepartmentByID(Resource):
    def get(self):
        department = [department.to_dict(only=("id","name","description")) for department in Department.query.filter(Department.id == id)]
        return make_response(jsonify(department),200)
    
    def patch(self,id):

        data = request.get_json()

        department = Department.query.filter(Department.id == id).first()

        for attr in data:

            setattr(department,attr,data.get(attr))   

        db.session.add(department)
        db.session.commit()

        return make_response(department.to_dict(only=('id',  'description', 'date_reported')),200)

    def delete(self,id):

        department = Department.query.filter(Department.id == id).first()

        if department:
            db.session.delete(department)
            db.session.commit()
            return make_response("",204)
        
        else:
            return make_response(jsonify({"error":"department not found"}),404)       
        
class Reports(Resource):
    def get(self):
       
            reports = [reports.to_dict(only=('id', 'title','description',"date_reported","user_id","user.name")) for reports in Report.query.all()]
            return make_response(jsonify(reports),200)
        
    def post(self):  
        data = request.json

        new_report = Report(
            title = data["title"],
            description = data["description"],
            user_id = data["user_id"],
            
            
            
        )

        db.session.add(new_report)
        db.session.commit()

        return make_response(jsonify(new_report.to_dict(only=('id', 'title','description',"date_reported","user_id","user.name"))),200) 
    
class ReportByID(Resource):
    def get(self):
        report = [report.to_dict(only=('id', 'title','description',"date_reported","user_id","user.name")) for report in Report.query.filter(Report.id == id)]
        return make_response(jsonify(report),200)
    
    def patch(self,id):

        data = request.get_json()

        report = Report.query.filter(Report.id == id).first()

        for attr in data:

            setattr(report,attr,data.get(attr))   

        db.session.add(report)
        db.session.commit()

        return make_response(report.to_dict(only=('id', 'title','description',"date_reported","user_id")),200)

    def delete(self,id):

        report = Report.query.filter(Report.id == id).first()

        if report:
            db.session.delete(report)
            db.session.commit()
            return make_response("",204)
        
        else:
            return make_response(jsonify({"error":"report not found"}),404)     
        
class Collections(Resource):
    def get(self):
       
            collections = [collections.to_dict(only=('type_of_collection', 'amount','created_at')) for collections in Collection.query.all()]
            return make_response(jsonify(collections),200)
        
    def post(self):  
        data = request.json

        new_collection = Collection(
            type_of_collection = data["type_of_collection"],
            amount = data["amount"],
            
            
            
            
        )

        db.session.add(new_collection)
        db.session.commit()

        return make_response(jsonify(new_collection.to_dict(only=('type_of_collection', 'amount','created_at'))),200) 
    
class CollectionByID(Resource):
    def get(self):
        collection = [collection.to_dict(only=('type_of_collection', 'amount','created_at')) for department in Collection.query.filter(Collection.id == id)]
        return make_response(jsonify(collection),200)
    
    def patch(self,id):

        data = request.get_json()

        collection = Collection.query.filter(Collection.id == id).first()

        for attr in data:

            setattr(collection,attr,data.get(attr))   

        db.session.add(collection)
        db.session.commit()

        return make_response(collection.to_dict(only=('type_of_collection', 'amount','created_at')),200)

    def delete(self,id):

        collection = Collection.query.filter(Collection.id == id).first()

        if collection:
            db.session.delete(collection)
            db.session.commit()
            return make_response("",204)
        
        else:
            return make_response(jsonify({"error":"Collection not found"}),404)                   

api.add_resource(UserRegister,"/userRegister")
api.add_resource(UserLogin,"/userLogin")
api.add_resource(Departments,"/departments")
api.add_resource(DepartmentByID,"/department/<int:id>")
api.add_resource(Reports,"/reports")
api.add_resource(ReportByID,"/report/<int:id>")
api.add_resource(Collections,"/collections")
api.add_resource(CollectionByID,"/collection/<int:id>")

if __name__ == "__main__":
    app.run(debug=True,port=5000)