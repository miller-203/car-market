const API_URL = ""; // Change this when deploying

function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/';
}