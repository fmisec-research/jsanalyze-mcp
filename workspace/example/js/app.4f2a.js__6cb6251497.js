(function() {
    const API = "https://api.target.tld/v1";
    fetch(`${API}/users/${userId}/orders/123`, {
        method: "GET"
    });
    axios.post("/api/admin/users/promote", {
        role: "admin"
    });
    fetch("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
            u,
            p
        })
    });
    axios.post("/api/v1/auth/reset-password", {
        email
    });
    fetch("/graphql", {
        method: "POST",
        body: JSON.stringify({
            query
        })
    });
    fetch("/api/v0/legacy/export?user_id=1");
    const ws = new WebSocket("wss://api.target.tld/socket");
    import("/chunks/admin-panel.js");
    const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    const STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH";
    const GMAPS = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
    el.innerHTML = location.hash;
    window.addEventListener("message", function(e) {
        document.getElementById("out").innerHTML = e.data;
    });
})();
//# sourceMappingURL=/static/js/app.4f2a.js.map