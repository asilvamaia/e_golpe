// ATENÇÃO: Substitua a URL abaixo pela URL pública da sua API no Railway
const API_URL = "https://SEU_APP_NO_RAILWAY.up.railway.app/api/v1/analyze";

document.addEventListener('DOMContentLoaded', async () => {
    const urlDisplay = document.getElementById('current-url');
    const analyzeBtn = document.getElementById('analyze-btn');
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const verdictEl = document.getElementById('verdict');
    const analysisTextEl = document.getElementById('analysis-text');

    // Pegar a URL da aba ativa
    let activeUrl = "";
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs.length > 0) {
            activeUrl = tabs[0].url;
            // Limitar exibição
            urlDisplay.textContent = activeUrl.length > 60 ? activeUrl.substring(0, 60) + '...' : activeUrl;
        } else {
            urlDisplay.textContent = "Não foi possível obter a URL atual.";
            analyzeBtn.disabled = true;
        }
    });

    analyzeBtn.addEventListener('click', async () => {
        if (!activeUrl) return;

        // Reset state
        analyzeBtn.classList.add('hidden');
        loadingDiv.classList.remove('hidden');
        resultDiv.classList.add('hidden');

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ text: activeUrl })
            });

            if (!response.ok) {
                throw new Error("Erro na comunicação com o servidor.");
            }

            const data = await response.json();

            if (data.status === 'success') {
                formatAndDisplayResult(data.analysis);
            } else {
                throw new Error("Erro na análise interna.");
            }

        } catch (error) {
            verdictEl.textContent = "Erro na Análise";
            verdictEl.className = "verdict-erro";
            analysisTextEl.textContent = "Não foi possível acessar a API GuardianBot. Verifique se o servidor ('" + API_URL + "') está online: " + error.message;
        } finally {
            loadingDiv.classList.add('hidden');
            resultDiv.classList.remove('hidden');
            analyzeBtn.classList.remove('hidden');
            analyzeBtn.textContent = "Re-Analisar";
        }
    });

    function formatAndDisplayResult(markdownText) {
        // Função simples para converter o Markdown do Gemini para algo visível
        // 1. Achar Veredito
        if (markdownText.includes("Veredito: **SEGURO**") || markdownText.includes("Veredito:** :green[**SEGURO**]") || markdownText.includes("SEGURO")) {
            verdictEl.textContent = "✅ SITE SEGURO";
            verdictEl.className = "verdict-seguro";
        } else if (markdownText.includes("GOLPE") || markdownText.includes("PHISHING") || markdownText.includes("MALWARE")) {
            verdictEl.textContent = "🚨 ALERTA DE GOLPE!";
            verdictEl.className = "verdict-golpe";
        } else if (markdownText.includes("ALERTA") || markdownText.includes("SUSPEITO")) {
            verdictEl.textContent = "⚠️ ATENÇÃO: SITE SUSPEITO";
            verdictEl.className = "verdict-alerta";
        } else {
            verdictEl.textContent = "ℹ️ ANÁLISE CONCLUÍDA";
            verdictEl.className = "verdict-erro";
        }

        // Limpar formatações de markdown básicas (*) do texto principal
        let textClean = markdownText.replace(/\*\*/g, ''); // Tira negrito
        textClean = textClean.replace(/#/g, ''); // Tira headers
        textClean = textClean.replace(/:green\[(.*?)\]/g, '$1'); // Limpeza customizada Streamlit
        textClean = textClean.replace(/:red\[(.*?)\]/g, '$1');

        // Adicionar quebras de linha em HTML
        analysisTextEl.innerHTML = textClean.split('\n').join('<br>');
    }
});
