// ============================================
// CryptoSuite Complete — Web App Logic
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // State
    let currentAlgo = 'cesar';
    let currentTP = 'tp1';

    // DOM refs
    const tpTabs = document.querySelectorAll('.tab');
    const algoLists = document.querySelectorAll('.algo-list');
    const algoBtns = document.querySelectorAll('.algo-btn');
    const inputText = document.getElementById('inputText');
    const outputText = document.getElementById('outputText');
    const keyInput = document.getElementById('keyInput');
    const ivInput = document.getElementById('ivInput');
    const btnExecute = document.getElementById('btnExecute');
    const btnClearInput = document.getElementById('btnClearInput');
    const btnExample = document.getElementById('btnExample');
    const btnLoadFile = document.getElementById('btnLoadFile');
    const fileInput = document.getElementById('fileInput');
    const btnSaveOutput = document.getElementById('btnSaveOutput');
    const btnCopyOutput = document.getElementById('btnCopyOutput');
    const btnClearLog = document.getElementById('btnClearLog');
    const logContent = document.getElementById('logContent');
    const statusBadge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const algoDescText = document.getElementById('algoDescText');
    const keyStatus = document.getElementById('keyStatus');
    const execTime = document.getElementById('execTime');
    const keyButtons = document.querySelectorAll('.btn-key');

    // Init
    initParticles();
    addLog('🚀 CryptoSuite Complete démarrée');
    addLog('📌 Tous les algorithmes des TPs 1 à 6 sont disponibles');

    // ==================== TAB SWITCHING ====================
    tpTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tp = tab.dataset.tp;
            currentTP = tp;
            tpTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            algoLists.forEach(l => l.style.display = 'none');
            document.getElementById(tp).style.display = 'flex';
        });
    });

    // ==================== ALGO SELECTION ====================
    algoBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            algoBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentAlgo = btn.dataset.algo;
            algoDescText.textContent = btn.dataset.desc;
            addLog(`📌 ${currentAlgo.toUpperCase()} sélectionné — ${btn.dataset.desc}`);
        });
    });

    // ==================== EXECUTE ====================
    btnExecute.addEventListener('click', async () => {
        const mode = document.querySelector('input[name="mode"]:checked').value;
        const text = inputText.value.trim();
        const key = keyInput.value.trim();

        setStatus('processing', '⏳ Traitement...');
        btnExecute.classList.add('loading');

        try {
            const res = await fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ algo: currentAlgo, mode, text, key })
            });
            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.error || 'Erreur serveur');
            }

            outputText.value = data.result;
            execTime.textContent = `✅ Terminé en ${data.time} ms`;
            setStatus('ready', 'Prêt');
            addLog(`${currentAlgo.toUpperCase()} — ${mode} terminé en ${data.time} ms`);
            showToast(`✅ ${currentAlgo.toUpperCase()} exécuté`, 'success');
        } catch (err) {
            outputText.value = `❌ Erreur: ${err.message}`;
            setStatus('error', 'Erreur');
            addLog(`❌ Erreur: ${err.message}`);
            showToast(`❌ ${err.message}`, 'error');
        } finally {
            btnExecute.classList.remove('loading');
        }
    });

    // ==================== KEY GENERATION ====================
    keyButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const type = btn.dataset.keytype;
            btn.classList.add('generating');
            btn.textContent = '⏳...';
            keyStatus.innerHTML = `<p>🔄 Génération ${type.toUpperCase()} en cours...</p>`;
            addLog(`🔑 Génération des clés ${type.toUpperCase()}...`);

            try {
                const res = await fetch('/api/gen_keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error);
                keyStatus.innerHTML = `<p>${data.info.replace(/\n/g, '<br>')}</p>`;
                addLog(`✅ ${type.toUpperCase()} généré avec succès`);
                showToast(`🔑 Clés ${type.toUpperCase()} générées`, 'success');
            } catch (err) {
                keyStatus.innerHTML = `<p>❌ Erreur: ${err.message}</p>`;
                addLog(`❌ Erreur ${type}: ${err.message}`);
                showToast(`❌ ${err.message}`, 'error');
            } finally {
                btn.classList.remove('generating');
                const labels = { rsa: 'RSA 2048', dh: 'DH', ecc: 'ECC', elgamal: 'ElGamal' };
                btn.textContent = labels[type] || type;
            }
        });
    });

    // ==================== UTILITIES ====================

    btnClearInput.addEventListener('click', () => {
        inputText.value = '';
        addLog('🗑️ Entrée effacée');
    });

    btnExample.addEventListener('click', () => {
        const examples = {
            cesar: 'Bonjour le monde! Ceci est un message secret.',
            vigenere: 'Ce message sera chiffre avec Vigenere',
            rsa: 'Message secret pour RSA',
            md5: 'Message a hacher avec MD5',
            bluetooth: 'Test Bluetooth',
            vote: 'Vote pour Alice'
        };
        inputText.value = examples[currentAlgo] || "Ceci est un exemple de message pour tester l'algorithme.";
        addLog(`📝 Exemple chargé pour ${currentAlgo}`);
    });

    btnLoadFile.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            inputText.value = ev.target.result;
            addLog(`📁 Fichier chargé: ${file.name}`);
        };
        reader.readAsText(file);
        fileInput.value = '';
    });

    btnSaveOutput.addEventListener('click', () => {
        const content = outputText.value;
        if (!content) return;
        const blob = new Blob([content], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `cryptosuite_${currentAlgo}_output.txt`;
        a.click();
        URL.revokeObjectURL(a.href);
        addLog('💾 Sortie sauvegardée');
        showToast('💾 Fichier sauvegardé', 'success');
    });

    btnCopyOutput.addEventListener('click', () => {
        const content = outputText.value;
        if (!content) return;
        navigator.clipboard.writeText(content).then(() => {
            addLog('📋 Copié dans le presse-papier');
            showToast('📋 Copié!', 'success');
        });
    });

    btnClearLog.addEventListener('click', () => { logContent.innerHTML = ''; });

    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            btnExecute.click();
        }
    });

    // ==================== HELPERS ====================

    function setStatus(type, text) {
        statusBadge.className = 'status-badge';
        if (type === 'processing') statusBadge.classList.add('processing');
        else if (type === 'error') statusBadge.classList.add('error');
        statusText.textContent = text;
    }

    function addLog(message) {
        const now = new Date();
        const ts = now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `<span class="log-time">[${ts}]</span> <span class="log-msg">${message}</span>`;
        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = '0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function initParticles() {
        const container = document.getElementById('bgParticles');
        for (let i = 0; i < 15; i++) {
            const p = document.createElement('div');
            p.className = 'particle';
            const size = Math.random() * 200 + 60;
            p.style.width = size + 'px';
            p.style.height = size + 'px';
            p.style.left = Math.random() * 100 + '%';
            p.style.top = Math.random() * 100 + '%';
            p.style.animationDelay = Math.random() * 10 + 's';
            p.style.animationDuration = (Math.random() * 15 + 15) + 's';
            container.appendChild(p);
        }
    }
});
