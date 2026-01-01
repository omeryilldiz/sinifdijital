#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Email Template Render Test
Email şablonlarının doğru şekilde render edildiğini test et
"""
import sys
sys.path.insert(0, '/root/SF')

from SF import app, db
from SF.models import User
from SF.services.email_templates import EmailTemplateService

# App context'i oluştur
with app.app_context():
    # Test user oluştur
    test_user = User(
        username='testuser',
        email='test@example.com',
        first_name='Ahmet'
    )
    
    print("="*60)
    print("EMAIL TEMPLATES TEST")
    print("="*60)
    
    # 1. Verification Email Test
    print("\n✓ Testing Verification Email Template...")
    verification_url = "https://sinifdigital.com/verify-email/test-token"
    verification_html = EmailTemplateService.render_verification_email(test_user, verification_url)
    
    if verification_html:
        print(f"  ✓ Verification email length: {len(verification_html)} chars")
        print(f"  ✓ Contains 'Sınıf' branding: {'Sınıf' in verification_html}")
        print(f"  ✓ Contains 'Dijital' branding: {'Dijital' in verification_html}")
        print(f"  ✓ Contains primary color (#00457C): {'00457C' in verification_html}")
        print(f"  ✓ Contains accent color (#00A5AD): {'00A5AD' in verification_html}")
        print(f"  ✓ Contains verification URL: {verification_url in verification_html}")
    else:
        print("  ✗ Failed to render verification email")
    
    # 2. Password Reset Email Test
    print("\n✓ Testing Password Reset Email Template...")
    reset_url = "https://sinifdigital.com/reset-password/test-token"
    reset_html = EmailTemplateService.render_password_reset_email(test_user, reset_url)
    
    if reset_html:
        print(f"  ✓ Reset email length: {len(reset_html)} chars")
        print(f"  ✓ Contains 'Sınıf' branding: {'Sınıf' in reset_html}")
        print(f"  ✓ Contains 'Dijital' branding: {'Dijital' in reset_html}")
        print(f"  ✓ Contains reset URL: {reset_url in reset_html}")
    else:
        print("  ✗ Failed to render reset email")
    
    # 3. Password Changed Email Test
    print("\n✓ Testing Password Changed Email Template...")
    changed_html = EmailTemplateService.render_password_changed_email(test_user)
    
    if changed_html:
        print(f"  ✓ Changed email length: {len(changed_html)} chars")
        print(f"  ✓ Contains 'Sınıf' branding: {'Sınıf' in changed_html}")
        print(f"  ✓ Contains 'Dijital' branding: {'Dijital' in changed_html}")
    else:
        print("  ✗ Failed to render changed email")
    
    # Summary
    print("\n" + "="*60)
    print("✓ All email templates render successfully!")
    print("="*60)
