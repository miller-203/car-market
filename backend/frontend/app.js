const API_URL = "http://localhost:3000"; // Change this when deploying

function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
}