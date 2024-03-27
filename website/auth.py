import datetime
import io
import requests
from .models import userdetail, db, User, shows , Favourite, Live, AdminUser
from .forms import RegistrationForm, ChangePasswordForm, LiveUploadForm , ProfileForm
from datetime import datetime
from . import db
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response
from website import cv2
from flask_login import current_user, login_required
from flask import Blueprint, request, jsonify
import base64
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash


auth = Blueprint('auth', __name__)

def init_auth(app, cam):
    app.camera = cam   


def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)

            # Check if the encoding was successful
            if ret:
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            else:
                # Log or handle the error as needed
                print("Error encoding frame.")



auth = Blueprint('auth', __name__)
camera = None

def init_auth(app, cam):
    global camera
    camera = cam

@auth.route('/resetuser', methods=['GET', 'POST'])
def resetuser():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            if request.form.get('save'):  # Check if the form is submitted to save changes
                # Update user data with the form values
                user.name = request.form.get('username')
                user.country = request.form.get('country')
                user.contact_number = request.form.get('phone-number')
                # Commit changes to the database
                db.session.commit()
                user_data = {  # Update user_data with the updated values
                    'username': user.name,
                    'email': user.email,
                    'country': user.country,
                    'phone_number': user.contact_number
                }
                flash('Changes saved successfully', 'success')
                return render_template('resetuser.html', user_data=user_data)  # Render template with updated data
            else:
                user_data = {
                    'username': user.name,
                    'email': user.email,
                    'country': user.country,
                    'phone_number': user.contact_number
                }
                return render_template('resetuser.html', user_data=user_data)
        else:
            error_message = 'User not found'
            return render_template('resetuser.html', error_message=error_message)
    else:
        return render_template('resetuser.html')
    

@auth.route('/update_password', methods=['POST'])
def update_password():
    email = request.form.get('email')
    new_password = request.form.get('newPassword')
    user = User.query.filter_by(email=email).first()
    if user:
        # Hash the new password and update the user's password
        user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully', 'success')
        user_data = {
            'username': user.name,
            'email': user.email,
            'country': user.country,
            'phone_number': user.contact_number
        }
        return render_template('resetuser.html', user_data=user_data, show_password_form=True)
    else:
        flash('User not found', 'error')
        return redirect(url_for('auth.resetuser'))
    

@auth.route('/userprofile', methods=['GET', 'POST'])
def userprofile():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        if request.method == 'POST':
            # Handle deletion of favorite show
            show_id = request.form.get('show_id')
            favorite_show = Favourite.query.filter_by(user_id=user.id, show_id=show_id).first()
            if favorite_show:
                # Delete the favorite show from the database
                db.session.delete(favorite_show)
                db.session.commit()
                flash('Favorite show deleted successfully', 'success')
                # Redirect to the same page to prevent form resubmission
                return redirect(url_for('auth.userprofile', email=email))

        # Fetch the user's favorite shows from the database again after deletion
        favorite_shows = Favourite.query.filter_by(user_id=user.id).all()
        return render_template('userprofile.html', user=user, favorite_shows=favorite_shows)
    else:
        flash('User not found', 'error')
        return redirect(url_for('auth.resetuser'))

@auth.route('/manageshow', methods=['GET', 'POST'])
def manageshow():
    if request.method == 'POST':
        # Fetch show data based on search input
        show_id = request.form.get('id')
        show = shows.query.filter_by(id=show_id).first()

        if show:
            # Update the show data if form data is submitted
            if 'save' in request.form:
                # Update show data with form values
                show.title = request.form['title']
                show.name = request.form['name']
                show.category = request.form['category']
                # Convert release date to datetime format
                release_date_str = request.form['release']
                show.release = datetime.strptime(release_date_str, '%Y-%m-%d')
                show.language = request.form['language']
                db.session.commit()
                flash('Show data updated successfully', 'success')
                # Redirect to the same page with updated show ID
                

            # Render the template with show_data
            return render_template('manageshow.html', show_data=show)
        else:
            # If show not found, display error message
            flash('Show not found', 'error')
            return render_template('manageshow.html', error_message='Show not found')

    # If request method is GET, render the template without any data
    return render_template('manageshow.html')

@auth.route('/delete_show/<int:show_id>', methods=['POST'])
def delete_show(show_id):
    # Fetch the show to be deleted from the database
    show = shows.query.get(show_id)

    if show:
        # Delete the show from the database
        db.session.delete(show)
        db.session.commit()
        flash('Show deleted successfully', 'success')
    else:
        flash('Show not found', 'error')

    # Redirect back to the manage show page
    return redirect(url_for('auth.manageshow'))


@auth.route('/adminshowdetail/<int:show_id>')
def adminshowdetail(show_id):
    # Fetch the show details from the database
    show = shows.query.get(show_id)

    if show:
        # Render the template with the show details
        return render_template('adminshowdetail.html', show=show)
    else:
        # If show not found, display an error message
        flash('Show not found', 'error')
        return redirect(url_for('auth.manageshow'))

@auth.route('/viewshow')
def viewshow():
    # Retrieve all shows from the database
    show_data = shows.query.all()
    return render_template('viewshow.html', show_data=show_data)
    


@auth.route('/admindashboard')
def admindashboard():
    # Retrieve counts from the database
    total_admins = AdminUser.query.count()
    total_users = User.query.count()
    # Count ongoing live shows (shows with release date equal to today)
    ongoing_live_shows = shows.query.filter(shows.release == datetime.today()).count()
    
    # Count total shows
    total_shows = shows.query.count()
    
    # Count upcoming shows (shows with release date greater than today's date)
    upcoming_shows = shows.query.filter(shows.release > datetime.today()).count()
    
    # Count previous shows (shows with release date earlier than today's date)
    previous_shows = shows.query.filter(shows.release < datetime.today()).count()
    
    # Count blocked users (users with role set to 'blocked')
    blocked_users = User.query.filter_by(role='blocked').count()

    

    return render_template('admindashboard.html', total_users=total_users, total_admins=total_admins,
                           ongoing_live_shows=ongoing_live_shows, total_shows=total_shows,
                           upcoming_shows=upcoming_shows, previous_shows=previous_shows,
                           blocked_users=blocked_users)






   
    
@auth.route('/adminindex')
def adminindex():
    return render_template('admindashboard.html')

@auth.route('/adminform')
def adminform():
    return render_template('adminform.html')

@auth.route('/admintable')
def admintable():
    users = User.query.all()
    # Unhash the passwords
    for user in users:
        unhashed_password = check_password_hash(user.password_hash, user.password_hash)
        user.password = unhashed_password
    return render_template('admintable.html', users=users)



@auth.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = AdminUser.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # Set the user session
            session['user_id'] = user.id
            session['user_name'] = user.username 
            return redirect(url_for('auth.admindashboard'))
            
        else:
            # If user doesn't exist or password is incorrect, show an alert
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('adminlogin.html')



@auth.route('/adminnew', methods=['GET', 'POST'])
def adminnew():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        contact = request.form.get('contact')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create new AdminUser object
        new_admin_user = AdminUser(username=username, email=email, hash_password=hashed_password, contact=contact)

        # Add the new user to the database
        db.session.add(new_admin_user)
        db.session.commit()

        # Flash message for success
        flash('Admin user added successfully!', 'success')

    # Render the form page
    return render_template('adminnew.html')





@auth.route('/live_upload', methods=['GET', 'POST'])
def live_upload():
    form = LiveUploadForm()
    if form.validate_on_submit():
        video_file = form.video.data
        new_live = Live(video=video_file.read())
        db.session.add(new_live)
        db.session.commit()
        return redirect(url_for('auth.live_upload'))
    return render_template('live_upload.html', form=form)






@auth.route('/live')
def live():
    user_id = session.get('user_id')
    user = User.query.get(user_id) if user_id else None
    active_tab = 'ongoing'
    upcoming_shows = shows.query.filter(shows.release > datetime.now()).all()
    previous_shows = shows.query.filter(shows.release < datetime.now()).all()
    live_shows = Live.query.all()
    return render_template('live.html', user=user, active_tab=active_tab, upcoming_shows=upcoming_shows, previous_shows=previous_shows, live_shows=live_shows)



    
@auth.route('auth/login.html')  # No need to include '/auth' in the route URL
def login():
    return render_template('login.html')

@auth.route('auth/index.html')  
def index():
    return render_template('index.html')


@auth.route('/auth/admin.html', methods=['GET', 'POST'])
def admin():
    user = session.get('user_id')  # Retrieve the user ID from the session

    # Fetch saved shows for the current user from the database
    if user:
        saved_shows = [fav.show_id for fav in Favourite.query.filter_by(user_id=user).all()]
    else:
        saved_shows = []

    if request.method == 'POST':
        show_id = request.form.get('show_id')
        
        # Check if the user is logged in
        if not user:
            flash('User not logged in', 'alert')
            return redirect(url_for('auth.admin'))

        # Check if the show ID is provided
        if not show_id:
            flash('Show ID not provided', 'alert')
            return redirect(url_for('auth.admin'))

        # Check if the user already saved this show as a favorite
        existing_favourite = Favourite.query.filter_by(user_id=user, show_id=show_id).first()
        if existing_favourite:
            flash('Show already saved as favourite', 'alert')
            return redirect(url_for('auth.admin'))

        # Save the show as a favorite
        new_favourite = Favourite(user_id=user, show_id=show_id)
        db.session.add(new_favourite)
        db.session.commit()

        # Store the saved show ID in session to highlight the heart icon
        saved_shows.append(show_id)
        session['saved_shows'] = saved_shows

        flash('Show saved as favourite', 'success')
        return redirect(url_for('auth.admin'))

    shows_data = shows.query.all()

    # Retrieve user object if user is logged in
    if user:
        user_obj = User.query.get(user)
    else:
        user_obj = None

    # Pass the user object to the template
    return render_template('admin.html', user=user_obj, shows_data=shows_data, saved_shows=saved_shows)

@auth.route('auth/usernav.html')  
def usernav():
    return render_template('usernav.html')






@auth.route('/auth/package.html')  
def package():
    user_id = session.get('user_id')

    # Check if the user is logged in
    if user_id:
        # Fetch the user object from the database based on the user_id
        user = User.query.get(user_id)
    else:
        user = None  # Set user to None if the user is not logged in

    return render_template('package.html', user=user)


@auth.route('/auth/checkout.html')  
def checkout():
    user_id = session.get('user_id')
    user_name = session.get('user_name')

    if user_id:
        # Fetch the user object from the database using the user_id
        user = User.query.get(user_id)
        return render_template('checkout.html', user=user)
    else:
        # Handle the case where user_id is not found in the session
        return redirect(url_for('auth.login'))





from flask import request

@auth.route('/auth/profile.html', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    form = ProfileForm() 

    # Check if the user is logged in
    if user_id:
        # Fetch the user object from the database or use the stored information as needed
        user = User.query.get(user_id)

        
        if request.method == 'POST':
            # Handle deletion of favorite show
            show_id = request.form.get('show_id')
            favorite_show = Favourite.query.filter_by(user_id=user_id, show_id=show_id).first()
            if favorite_show:
                # Delete the favorite show from the database
                db.session.delete(favorite_show)
                db.session.commit()
                flash('Favorite show deleted successfully', 'success')

        # Fetch the user's favorite shows from the database again after deletion
        favorite_shows = Favourite.query.filter_by(user_id=user_id).all()

        return render_template('profile.html', user=user, user_name=user_name, favorite_shows=favorite_shows, form=form)
    else:
        return redirect(url_for('auth.login'))  # Redirect to login page if user is not logged in



@auth.route('auth/event.html')  
def event():
    # Retrieve the user information from the session
    user_id = session.get('user_id')
    user_name = session.get('user_name')

# Check if the user is logged in
    if user_id is not None:
        # Fetch the user object from the database or use the stored information as needed
        user = User.query.get(user_id)
    shows_data = shows.query.all()
    unique_categories = shows.query.distinct(shows.category).group_by(shows.category).all()
    print(60000+len(shows_data))
    return render_template('event.html', unique_categories=unique_categories, shows_data=shows_data,user=user, user_name=user_name)
   

@auth.route('/register.html', methods=['GET', 'POST'])  # No need to include '/auth' in the route URL
def register():
    print("Entered the register route.")
    form = RegistrationForm()

    if request.method == 'POST' and form.validate():
        print("Form is valid and submitted.")

        # Registration logic here
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        name = form.name.data
        country = form.country.data
        contact_number = form.contact_number.data    

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('auth.register'))

        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered', 'error')
            return redirect(url_for('auth.register'))

        # Create a new user
        new_user = User(email=email, name=name, country=country, contact_number=contact_number)
        new_user.set_password(password)

        # Save the user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('auth.login'))  # Corrected redirection

    else:
        print("Form validation errors:", form.errors)

    country_names = get_country_names()
    return render_template('register.html', form=form, country_names=country_names)

def get_country_names():
    api_endpoint = 'https://restcountries.com/v3.1/all'
    
    response = requests.get(api_endpoint)

    if response.status_code == 200:
        countries = response.json()
        country_names = [country['name']['common'] for country in countries]
        sorted_country_names = sorted(country_names)
        return sorted_country_names
    else:
        return []

@auth.route('/login', methods=['GET', 'POST'])
def loginn():
    if 'user_id' in session:
        # Fetch the user object from the database or use the stored information as needed
        user = User.query.get(session['user_id'])
        shows_data = shows.query.all()

        # Fetch saved shows for the current user from the database
        saved_shows = [fav.show_id for fav in Favourite.query.filter_by(user_id=user.id).all()]

        return render_template('admin.html', user=user, shows_data=shows_data, saved_shows=saved_shows)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Find the user by email
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password is correct
        if user and user.check_password(password):
            # Set the user session
            session['user_id'] = user.id
            session['user_name'] = user.name 

            # Fetch shows data from the database
            shows_data = shows.query.all()

            # Fetch saved shows for the current user from the database
            saved_shows = [fav.show_id for fav in Favourite.query.filter_by(user_id=user.id).all()]

            # Render admin page with user and shows data
            return render_template('admin.html', user=user, shows_data=shows_data, saved_shows=saved_shows)
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')


@auth.route('/firm', methods=['GET', 'POST'])
def firm():
    if request.method == 'POST':
        try:
            name = request.form['name']
            title = request.form['title']
            description = request.form['description']
            category = request.form['category']
            release_date_str = request.form['releaseDate'] 
            release_date = datetime.strptime(release_date_str, '%Y-%m-%d').date()  # Convert string to date
            language = request.form['language']
            duration = request.form['duration']

            # Check if media file and image file are provided
            if 'uploadMedia' not in request.files or 'uploadImage' not in request.files:
                flash('Media file or image file not provided', 'error')
                return redirect(url_for('auth.firm'))

            # Read media file
            media_file = request.files['uploadMedia']
            if media_file.filename == '':
                flash('Media file not selected', 'error')
                return redirect(url_for('auth.firm'))
            media = media_file.read()

            # Read image file
            image_file = request.files['uploadImage']
            if image_file.filename == '':
                flash('Image file not selected', 'error')
                return redirect(url_for('auth.firm'))
            image = image_file.read()
           
            
            # Save data to the database
            new_show = shows(name=name, title=title, description=description, category=category,
                            release=release_date, language=language, duration=duration, media=media, cover=image)

            db.session.add(new_show)
            db.session.commit()

            flash('Files uploaded successfully', 'success')
        except Exception as e:
            flash(f'Error uploading files: {str(e)}', 'error')
            return redirect(url_for('auth.firm'))

    return render_template('firm.html')





@auth.route('/detail/<int:show_id>')
def detail(show_id):
    # Retrieve the user ID and user name from the session
    user_id = session.get('user_id')
    user_name = session.get('user_name')

    # Check if the user is logged in
    if user_id:
        # Fetch the user object from the database
        user = User.query.get(user_id)
    else:
        user = None

    # Fetch the show details from the database based on the show_id
    show = shows.query.get_or_404(show_id)

    # Render the show detail template with the user and show data
    return render_template('showdetail.html', user=user, user_name=user_name, show=show)




@auth.route('/change_password', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Perform password change logic (e.g., updating the password in the database)

        flash('Password changed successfully', 'success')
        return redirect(url_for('views.home'))

    return render_template('change_password.html', form=form)

@auth.route('/favourite', methods=['GET', 'POST'])
def favourite():
    user_id = session.get('user_id')  # Retrieve the user ID from the session
    if request.method == 'POST':
        if user_id:
            # Get the show_id from the form data
            show_id = request.form.get('show_id')
            # Delete the favorite from the database
            favourite = Favourite.query.filter_by(user_id=user_id, show_id=show_id).first()
            if favourite:
                db.session.delete(favourite)
                db.session.commit()
                flash('Show removed from favorites successfully', 'success')
            else:
                flash('Show not found in favorites', 'error')
        else:
            flash('You must be logged in to perform this action', 'error')
    
    if user_id:
        favourites = Favourite.query.filter_by(user_id=user_id).all()
        user = User.query.get(user_id)
    else:
        favourites = []
        user = None
    return render_template('favourite.html', user=user, favourites=favourites)


from flask import send_file

@auth.route('/cover/<int:show_id>')
def cover(show_id):
    show = shows.query.get_or_404(show_id)
    return send_file(show.cover, mimetype='image/jpeg')  # Adjust mimetype as per your image type


@auth.route('/auth/favourite', methods=['POST'])
def delete_favorite():
    if request.method == 'POST':
        show_id = request.form.get('show_id')
        # Delete the favorite show from the database based on the show_id
        # Add your database deletion logic here
        return 'Favorite show deleted successfully', 200
    else:
        # Return an error response if the request method is not supported
        return 'Method Not Allowed', 405
    


@auth.route('/logout', methods=['GET'])
def logout():
    # Clear the user session
    session.clear()
    # Redirect the user to the login page or any other desired page
    return redirect(url_for('auth.login'))

@auth.route('/adminlogout')
def adminlogout():
    # Clear the session
    session.clear()
    # Redirect to the adminlogin page
    return redirect(url_for('auth.adminlogin'))

