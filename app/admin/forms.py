from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, Length, Optional

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Temporary Password', validators=[DataRequired(), Length(min=8, max=255)])
    is_admin = BooleanField('Admin')
    submit = SubmitField('Create User')

class ResetPasswordForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    password = PasswordField('New Temporary Password', validators=[DataRequired(), Length(min=8, max=255)])
    submit = SubmitField('Reset Password')

class ToggleActiveForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    active = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Toggle Active')

class ResetTOTPForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Reset 2FA')

class UnbindCertForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    fingerprint = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Revoke Certificate')

class BindCurrentCertForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Bind Current Client Certificate')

class IssueClientCertForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    p12_password = PasswordField('P12 Export Password', validators=[DataRequired(), Length(min=6, max=255)])
    ca_password = PasswordField('CA Signing Password', validators=[DataRequired(), Length(min=6, max=255)])
    submit = SubmitField('Issue Client Certificate (.p12)')
