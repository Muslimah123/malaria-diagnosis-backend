import click
from flask.cli import with_appcontext

@click.command('optimize-db')
@with_appcontext
def optimize_db_command():
    from flask import current_app
    from .database_management import optimize_database
    from .data_archiver import DataArchiver
    
    click.echo('Optimizing database...')
    optimize_database()
    
    click.echo('Creating archive tables...')
    data_archiver = DataArchiver(current_app.extensions['sqlalchemy'].db)
    data_archiver.create_archive_tables()
    
    click.echo('Database optimization completed.')