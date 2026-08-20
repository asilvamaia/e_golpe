class SecurityTip {
  final String title;
  final String category;
  final String icon;
  final String description;
  final List<String> howItWorks;
  final List<String> howToProtect;
  final String realExample;

  const SecurityTip({
    required this.title,
    required this.category,
    required this.icon,
    required this.description,
    required this.howItWorks,
    required this.howToProtect,
    required this.realExample,
  });

  static List<SecurityTip> getDefaultTips() {
    return const [
      SecurityTip(
        title: "Golpe do Falso Advogado / Alvará Judicial",
        category: "Justiça e Processos",
        icon: "⚖️",
        description: "Criminosos usam dados públicos de processos e se passam pelo seu advogado exigindo pagamento de taxas para liberar valores ganhos.",
        howItWorks: [
          "O golpista envia mensagem pelo WhatsApp com foto e nome do seu advogado real.",
          "Afirma que o processo judicial foi ganho e o alvará de pagamento foi expedido.",
          "Exige um Pix urgente para pagar 'custas cartorárias' ou 'certidão de liberação'."
        ],
        howToProtect: [
          "NUNCA faça pagamentos antecipados para liberar valores judiciais.",
          "Ligue para o número antigo do seu advogado (não responda pelo número novo que te chamou).",
          "Tribunais e varas nunca cobram PIX antecipado para liberar precatórios ou RPV."
        ],
        realExample: "'Dr. Carlos: Olá, seu alvará de R\$ 45.000 foi liberado pelo TJ. Precisamos recolher a guia de custas de R\$ 1.250 via Pix até as 16h para depósito em conta.'",
      ),
      SecurityTip(
        title: "Golpe do Falso Parente / Novo Número",
        category: "WhatsApp e Família",
        icon: "👨‍👩‍👧",
        description: "Golpistas entram em contato fingindo ser filho(a) ou neto(a) com número novo pedindo dinheiro para pagar contas urgentes.",
        howItWorks: [
          "Envia mensagem: 'Oi mãe/pai, troquei de celular, anota o número novo'.",
          "Logo em seguida relata que o app do banco está bloqueado no aparelho novo.",
          "Pede uma transferência via Pix urgente para pagar um boleto ou fornecedor."
        ],
        howToProtect: [
          "Faça uma ligação de voz/vídeo para o número antigo do seu parente.",
          "Faça perguntas pessoais que apenas o verdadeiro parente saberia responder.",
          "Nunca faça PIX por pressão ou urgência sem falar pessoalmente."
        ],
        realExample: "'Oi pai, meu celular caiu na água e estou usando este provisório. Preciso pagar um boleto do curso agora e meu app não abre, pode me ajudar?'",
      ),
      SecurityTip(
        title: "Golpe da Falsa Central Telefônica",
        category: "Bancos e Cartões",
        icon: "🏦",
        description: "Vítima recebe ligação ou SMS afirmando que houve uma compra suspeita de alto valor e é orientada a transferir para uma 'conta segura'.",
        howItWorks: [
          "SMS alarmista: 'Compra de R\$ 3.890 aprovada nas Casas Bahia. Se não reconhece, ligue 0800...'.",
          "Na ligação, uma falsa atendente com música de espera simula um atendimento bancário.",
          "Orienta a vítima a fazer um Pix de cancelamento ou instalar um aplicativo espião (TeamViewer, AnyDesk)."
        ],
        howToProtect: [
          "Bancos NUNCA pedem para você fazer PIX para cancelar compras.",
          "Bancos NUNCA pedem para você instalar programas no celular.",
          "Desligue a chamada e consulte seu extrato no aplicativo oficial do banco."
        ],
        realExample: "'BANCO: Compra aprovada de R\$ 4.750,00 no Mercado Livre. Caso desconheça, ligue agora para 0800 777 0192.'",
      ),
      SecurityTip(
        title: "Golpe do Presente / Brinde de Aniversário",
        category: "Entregas e Frete",
        icon: "🎁",
        description: "Um entregador vai até sua casa com flores ou chocolates dizendo ser um presente, mas exige pagar uma 'pequena taxa de entrega' na maquininha.",
        howItWorks: [
          "O motoboy chega com um lindo brinde sem remetente claro.",
          "Informa que o presente está pago, mas a taxa de entrega (R\$ 5 a R\$ 10) deve ser paga no cartão.",
          "A maquininha adulterada clona o cartão ou cobra valores de milhares de reais com visor apagado."
        ],
        howToProtect: [
          "Não aceite presentes misteriosos que exijam pagamento de frete na porta.",
          "Nunca pague nada em maquininhas com visor quebrado, ilegível ou coberto.",
          "Se insistirem, recuse a entrega."
        ],
        realExample: "'Bom dia! Temos uma cesta de chocolates de presente de aniversário para a senhora, só precisa pagar a taxa de R\$ 7,90 no cartão.'",
      ),
      SecurityTip(
        title: "Golpe dos Correios / Taxa de Alfândega",
        category: "Encomendas e Compras",
        icon: "📦",
        description: "SMS e e-mails falsos afirmando que sua encomenda está retida e será devolvida se você não pagar uma taxa imediatamente.",
        howItWorks: [
          "Mensagem com link encurtado imitando o site dos Correios (ex: correios-rastreio.site).",
          "O site falso solicita CPF e gera um código Pix para liberação imediata da encomenda.",
          "O dinheiro vai direto para a conta de laranjas e a mercadoria nem existe."
        ],
        howToProtect: [
          "Rastreie encomendas APENAS no site oficial dos Correios (correios.com.br) ou pelo app oficial.",
          "Taxas de importação são pagas exclusivamente no ambiente 'Minhas Importações' do site oficial.",
          "Desconfie de links que terminem em .site, .online, .top ou domínios estranhos."
        ],
        realExample: "'CORREIOS: Sua encomenda BR92837192 está retida na alfândega. Efetue o pagamento da taxa para liberação: https://rastreio-correios.me/taxa'",
      ),
      SecurityTip(
        title: "Golpe da Falsa Vaga de Emprego / Tarefas",
        category: "Renda Extra e Vagas",
        icon: "💼",
        description: "Promessas de altos ganhos diários para curtir vídeos no YouTube, avaliar produtos na Shein/Amazon ou investir em criptoativos.",
        howItWorks: [
          "Contato no WhatsApp ou Telegram oferecendo R\$ 200 a R\$ 1.000 por dia para tarefas simples.",
          "Pagam pequenas quantias reais no início para ganhar a confiança da vítima.",
          "Depois exigem 'depósitos de garantia' crescentes para liberar o saldo acumulado."
        ],
        howToProtect: [
          "Nenhuma empresa séria cobra dinheiro para você trabalhar.",
          "Desconfie de promessas de ganhos fáceis e rápidos na internet.",
          "Não forneça dados bancários nem faça depósitos para liberar comissões."
        ],
        realExample: "'Olá! Somos da equipe de recrutamento da Amazon. Você foi selecionado para avaliar produtos e ganhar de R\$ 300 a R\$ 800 por dia pelo celular.'",
      ),
    ];
  }
}
