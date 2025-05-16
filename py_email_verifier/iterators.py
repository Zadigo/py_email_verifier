import csv

from zemailer.patterns import Emails
from zemailer.validation.validators import validate


def verify_from_name(name, surname):
    """Using a name and a surname, verify that
    we can email to one or many of the created
    email addresses"""
    instance = Emails(name, surname)
    for email in instance:
        yield email, validate(email)


def verify_from_file(filename):
    """From a file containing names and surnames verify that
    we can send emails to one or many of the elements
    """
    with open(filename, mode='r', encoding='utf-8') as f:
        reader = list(csv.reader(f))
        has_firstname = 'firstname' in reader[0]
        has_lastname = 'lastname' in reader[0]
        if not has_firstname or not has_lastname:
            raise
        reader.pop(0)
        for item in reader:
            yield f'{item[0]} {item[1]}', verify_from_name(item[0], item[1])
