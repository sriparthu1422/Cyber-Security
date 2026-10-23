from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UploadLogForm(FlaskForm):
    log_file = FileField('Upload Log/Data File', validators=[
        FileRequired(),
        FileAllowed(['txt', 'log', 'csv', 'json'], 'Text, Log, CSV, or JSON files only!')
    ])
    source_type = SelectField('Data Source Type', choices=[
        ('network_traffic', 'Network Traffic'),
        ('system_log', 'System Log'),
        ('user_activity', 'User Activity Log'),
        ('transaction_record', 'Transaction Record'),
        ('email_content', 'Email Content'),
        ('malware_sample', 'Malware Sample')
    ], validators=[DataRequired()])
    submit = SubmitField('Ingest & Analyze Data')

class AlertResolutionForm(FlaskForm):
    comment = TextAreaField('Resolution Comment (Optional)')
    submit = SubmitField('Resolve Alert')