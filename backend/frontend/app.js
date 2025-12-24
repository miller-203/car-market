const API_URL = "http://127.0.0.1:3000"; // Change this when deploying

function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/';
}