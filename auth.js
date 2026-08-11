document.getElementById('login-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const userField = document.getElementById('username').value.trim();
    const passField = document.getElementById('password').value.trim();
    const alertBox = document.getElementById('auth-alert');

    // Default Ingestion Admin Profile Setup Configuration (Mee choices batti custom identity keys modify chesko mawa)
    const secureIdentityToken = "admin";
    const secureKeyPasscode = "password";

    if (userField === secureIdentityToken && passField === secureKeyPasscode) {
        // Success Condition Trigger Loops
        alertBox.classList.remove('hidden', 'bg-red-50', 'text-red-700', 'border-red-200');
        alertBox.classList.add('block', 'bg-green-50', 'text-green-700', 'border-green-200');
        alertBox.innerHTML = '<i class="fas fa-circle-check mr-1.5"></i> Access authorization approved. Syncing console logs...';

        // Redirect Target execution path directly inside your primary core metrics folder structure panel node
        setTimeout(() => {
            window.location.href = "dashboard/dashboard.html";
        }, 1200);
        
    } else {
        // Failure Conditions Trigger Handlers
        alertBox.classList.remove('hidden', 'bg-green-50', 'text-green-700', 'border-green-200');
        alertBox.classList.add('block', 'bg-red-50', 'text-red-700', 'border-red-200');
        alertBox.innerHTML = '<i class="fas fa-triangle-exclamation mr-1.5"></i> Verification failed. Incorrect tracking identity codes.';
    }
});