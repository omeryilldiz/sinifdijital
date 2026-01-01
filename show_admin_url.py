"""
Flask CLI komutu: Admin URL'ini gösterir
Kullanım: flask show-admin-url
"""
from SF import app
import click

@app.cli.command('show-admin-url')
def show_admin_url():
    """Admin panel URL'sini gösterir"""
    admin_url = app.config.get('ADMIN_URL_PREFIX', '/admin')
    server_name = app.config.get('SERVER_NAME', 'localhost:5000')
    
    click.echo("\n" + "="*60)
    click.echo("🔐 ADMIN PANEL BİLGİLERİ")
    click.echo("="*60)
    click.echo(f"📍 Admin URL Path: {admin_url}")
    click.echo(f"🌐 Full URL: http://{server_name}{admin_url}")
    click.echo(f"🍯 Honeypot (Sahte): /admin")
    click.echo("="*60)
    click.echo("\n⚠️  Bu URL'yi güvenli bir yerde saklayın!")
    click.echo("💡 .env dosyasında: ADMIN_URL_PREFIX değişkeni\n")

if __name__ == '__main__':
    show_admin_url()
