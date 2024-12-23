// static/js/login_toggle.js
function toggleUserType(type) {
    document.querySelectorAll('.toggle-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.login-form').forEach(form => form.style.display = 'none');
    
    if (type === 'business') {
        document.querySelector('#business-login').style.display = 'block';
        document.querySelector('button[onclick="toggleUserType(\'business\')"]').classList.add('active');
    } else {
        document.querySelector('#customer-login').style.display = 'block';
        document.querySelector('button[onclick="toggleUserType(\'customer\')"]').classList.add('active');
    }
}