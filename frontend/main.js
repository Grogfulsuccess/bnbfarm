// ==============================
//  CONFIG
// ==============================

// 👉 Remplace l'URL du backend par celle fournie par Railway
const API_BASE = "https://ton-backend.railway.app";

// ==============================
//  AUTHENTIFICATION PAR EMAIL
// ==============================

const loginForm = document.getElementById("loginForm");
const logoutBtn = document.getElementById("logoutBtn");

function saveUser(user) {
    localStorage.setItem("bnbfarm_user", JSON.stringify(user));
}

function getUser() {
    const u = localStorage.getItem("bnbfarm_user");
    if (!u) return null;
    return JSON.parse(u);
}

function logout() {
    localStorage.removeItem("bnbfarm_user");
    window.location.reload();
}

if (logoutBtn) {
    logoutBtn.onclick = logout;
}

if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const email = document.getElementById("email").value;

        const res = await fetch(`${API_BASE}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });

        const data = await res.json();

        if (data.error) {
            alert(data.error);
            return;
        }

        saveUser(data.user);
        window.location.href = "dashboard.html";
    });
}

// ==============================
//  CHARGER DASHBOARD
// ==============================

async function loadDashboard() {
    const user = getUser();
    if (!user) return;

    document.getElementById("userEmail").innerText = user.email;

    const res = await fetch(`${API_BASE}/user/${user.id}`);
    const data = await res.json();

    document.getElementById("balance").innerText = data.balance;
    document.getElementById("totalInvest").innerText = data.totalInvest;
    document.getElementById("totalProfits").innerText = data.totalProfits;
    document.getElementById("refLink").innerText = `${window.location.origin}/?ref=${user.id}`;
}

// ==============================
//  FAIRE UN DÉPÔT
// ==============================

async function makeDeposit() {
    const user = getUser();
    if (!user) {
        alert("Connectez-vous d'abord");
        return;
    }

    const amount = document.getElementById("depositAmount").value;

    if (!amount || amount <= 0) {
        alert("Montant invalide");
        return;
    }

    const res = await fetch(`${API_BASE}/deposit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            userId: user.id,
            amount
        })
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    alert("Dépôt enregistré ! Le rendement arrivera dans 5 minutes.");
    loadDashboard();
}

// ==============================
//  RETRAIT
// ==============================

async function makeWithdraw() {
    const user = getUser();
    if (!user) {
        alert("Connectez-vous d'abord");
        return;
    }

    const address = document.getElementById("withdrawAddress").value;
    const amount = document.getElementById("withdrawAmount").value;

    if (!address || !amount) {
        alert("Champs manquants");
        return;
    }

    const res = await fetch(`${API_BASE}/withdraw`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            userId: user.id,
            address,
            amount
        })
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    alert("Retrait envoyé !");
    loadDashboard();
}

// ==============================
//  CHARGER AUTO SI SUR DASHBOARD
// ==============================

if (window.location.pathname.includes("dashboard.html")) {
    loadDashboard();
}
