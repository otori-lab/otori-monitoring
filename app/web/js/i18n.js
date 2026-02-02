/**
 * OTORI Dashboard - Internationalization (i18n)
 * Translations and language management
 */

const I18N = {
  fr: {
    nav: { overview: "Vue d'ensemble", geography: "Géographie", sessions: "Sessions", analytics: "Analyse" },
    kpi: {
      totalSessions: "Total Sessions", uniqueIps: "IPs Uniques", commands: "Commandes",
      avgDuration: "Durée Moyenne", last24h: "dernières 24h", distinctAttackers: "attaquants distincts",
      perSession: "par session", criticalCmds: "Commandes Critiques", criticalLevel: "niveau critique",
      highSessions: "Sessions High+", highDanger: "danger élevé", mitreTechniques: "Techniques MITRE",
      detected: "détectées", botRatio: "Ratio Bots", vsHumans: "vs humains"
    },
    section: {
      activityTimeline: "Chronologie d'activité", threatDistribution: "Distribution des menaces",
      detailedAnalysis: "Analyse détaillée"
    },
    card: {
      authentication: "Authentification", topIps: "Top IPs", attackCategories: "Catégories d'Attaque",
      cmdSeverity: "Sévérité des Commandes", dangerousCmds: "Commandes les plus dangereuses",
      mitreTechniques: "Techniques MITRE ATT&CK", topPasswords: "Mots de passe fréquents"
    },
    auth: { success: "Succès", failed: "Échecs", usernames: "Identifiants", passwords: "Mots de passe" },
    table: {
      allSessions: "Toutes les Sessions", sourceIp: "IP Source", country: "Pays",
      username: "Identifiant", cmds: "Cmds", dangerScore: "Score", level: "Niveau",
      attacker: "Attaquant", duration: "Durée"
    },
    tooltip: { dangerScore: "Score 0-100 basé sur: sévérité, catégories, logins, durée" },
    chart: { sessions: "Sessions", commands: "Commandes", success: "Succès", failed: "Échecs" },
    empty: { noData: "Aucune donnée", noSession: "Aucune session" },
    filter: {
      title: "Filtres", ip: "IP", username: "Identifiant", country: "Pays",
      allCountries: "Tous les pays", dangerLevel: "Niveau de danger",
      attackerType: "Type d'attaquant", scoreRange: "Score (0-100)",
      cmdCount: "Commandes", honeypotType: "Type Honeypot", flags: "Indicateurs",
      persistence: "Persistence", credential: "Accès credentials",
      all: "Tous", reset: "Reinitialiser",
      results: "{count} session(s)", noResults: "Aucune session",
      activeFilters: "{count} filtre(s) actif(s)"
    },
    modal: {
      sessions: "Sessions", commands: "Commandes", avgScore: "Score moyen",
      totalDuration: "Durée totale", usernames: "Identifiants",
      dangerDistribution: "Distribution des niveaux de danger",
      sessionsList: "Sessions de cette IP", attackProfile: "Profil d'attaque",
      topCommands: "Commandes les plus utilisées", usernamesUsed: "Identifiants utilisés",
      attackerType: "Type d'attaquant", honeypotType: "Type de honeypot",
      firstSeen: "Première connexion", lastSeen: "Dernière connexion",
      noCommands: "Aucune commande enregistrée",
      filterByIp: "Filtrer par cette IP"
    },
    detail: {
      authSuccess: "Authentifications Réussies",
      authFailed: "Authentifications Échouées",
      commandSearch: "Recherche de commande",
      categoryCommands: "Commandes - Catégorie",
      severityCommands: "Commandes - Sévérité",
      countryDetails: "Sessions par pays",
      mitreTechnique: "Technique MITRE",
      passwordAttempts: "Tentatives avec ce mot de passe",
      usernameAttempts: "Tentatives avec cet identifiant",
      loading: "Chargement...",
      noResults: "Aucun résultat",
      totalEvents: "Total événements",
      uniqueIps: "IPs uniques",
      executions: "Exécutions",
      viewIp: "Voir cette IP",
      timestamp: "Horodatage"
    },
    geo: {
      uniqueCountries: "Pays uniques",
      origins: "origines distinctes",
      topCountry: "Pays #1",
      attackPoints: "Points d'attaque",
      geolocated: "géolocalisés",
      topAsn: "Top ASN",
      attackMap: "Carte des attaques",
      globalView: "Vue globale",
      topCountries: "Top Pays",
      topAsns: "Top ASN / Opérateurs",
      attacks: "attaques",
      uniqueIps: "IPs uniques",
      recentIps: "IPs récentes",
      more: "de plus"
    }
  },
  en: {
    nav: { overview: "Overview", geography: "Geography", sessions: "Sessions", analytics: "Analytics" },
    kpi: {
      totalSessions: "Total Sessions", uniqueIps: "Unique IPs", commands: "Commands",
      avgDuration: "Avg Duration", last24h: "last 24h", distinctAttackers: "distinct attackers",
      perSession: "per session", criticalCmds: "Critical Commands", criticalLevel: "critical level",
      highSessions: "High+ Sessions", highDanger: "high danger", mitreTechniques: "MITRE Techniques",
      detected: "detected", botRatio: "Bot Ratio", vsHumans: "vs humans"
    },
    section: {
      activityTimeline: "Activity Timeline", threatDistribution: "Threat Distribution",
      detailedAnalysis: "Detailed Analysis"
    },
    card: {
      authentication: "Authentication", topIps: "Top IPs", attackCategories: "Attack Categories",
      cmdSeverity: "Command Severity", dangerousCmds: "Most Dangerous Commands",
      mitreTechniques: "MITRE ATT&CK Techniques", topPasswords: "Common Passwords"
    },
    auth: { success: "Success", failed: "Failed", usernames: "Usernames", passwords: "Passwords" },
    table: {
      allSessions: "All Sessions", sourceIp: "Source IP", country: "Country",
      username: "Username", cmds: "Cmds", dangerScore: "Score", level: "Level",
      attacker: "Attacker", duration: "Duration"
    },
    tooltip: { dangerScore: "Score 0-100 based on: severity, categories, logins, duration" },
    chart: { sessions: "Sessions", commands: "Commands", success: "Success", failed: "Failed" },
    empty: { noData: "No data", noSession: "No session" },
    filter: {
      title: "Filters", ip: "IP", username: "Username", country: "Country",
      allCountries: "All countries", dangerLevel: "Danger Level",
      attackerType: "Attacker Type", scoreRange: "Score (0-100)",
      cmdCount: "Commands", honeypotType: "Honeypot Type", flags: "Indicators",
      persistence: "Persistence", credential: "Credential Access",
      all: "All", reset: "Reset",
      results: "{count} session(s)", noResults: "No sessions",
      activeFilters: "{count} active filter(s)"
    },
    modal: {
      sessions: "Sessions", commands: "Commands", avgScore: "Avg Score",
      totalDuration: "Total Duration", usernames: "Usernames",
      dangerDistribution: "Danger Level Distribution",
      sessionsList: "Sessions from this IP", attackProfile: "Attack Profile",
      topCommands: "Most Used Commands", usernamesUsed: "Usernames Used",
      attackerType: "Attacker Type", honeypotType: "Honeypot Type",
      firstSeen: "First Seen", lastSeen: "Last Seen",
      noCommands: "No commands recorded",
      filterByIp: "Filter by this IP"
    },
    detail: {
      authSuccess: "Successful Authentications",
      authFailed: "Failed Authentications",
      commandSearch: "Command Search",
      categoryCommands: "Commands - Category",
      severityCommands: "Commands - Severity",
      countryDetails: "Sessions by Country",
      mitreTechnique: "MITRE Technique",
      passwordAttempts: "Attempts with this password",
      usernameAttempts: "Attempts with this username",
      loading: "Loading...",
      noResults: "No results",
      totalEvents: "Total events",
      uniqueIps: "Unique IPs",
      executions: "Executions",
      viewIp: "View this IP",
      timestamp: "Timestamp"
    },
    geo: {
      uniqueCountries: "Unique Countries",
      origins: "distinct origins",
      topCountry: "Top Country",
      attackPoints: "Attack Points",
      geolocated: "geolocated",
      topAsn: "Top ASN",
      attackMap: "Attack Map",
      globalView: "Global View",
      topCountries: "Top Countries",
      topAsns: "Top ASN / Operators",
      attacks: "attacks",
      uniqueIps: "Unique IPs",
      recentIps: "Recent IPs",
      more: "more"
    }
  }
};

let currentLang = localStorage.getItem('otori-lang') || 'fr';

function t(key) {
  const keys = key.split('.');
  let val = I18N[currentLang];
  for (const k of keys) {
    val = val?.[k];
  }
  return val || key;
}

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-tooltip]').forEach(el => {
    el.setAttribute('data-tooltip', t(el.dataset.i18nTooltip));
  });
  document.getElementById('lang-toggle').textContent = currentLang.toUpperCase();

  // Update chart labels
  if (typeof activityChart !== 'undefined' && activityChart) {
    activityChart.data.datasets[0].label = t('chart.sessions');
    activityChart.data.datasets[1].label = t('chart.commands');
    activityChart.update('none');
  }
  if (typeof loginChart !== 'undefined' && loginChart) {
    loginChart.data.labels = [t('chart.success'), t('chart.failed')];
    loginChart.update('none');
  }
}

function toggleLanguage() {
  currentLang = currentLang === 'fr' ? 'en' : 'fr';
  localStorage.setItem('otori-lang', currentLang);
  applyTranslations();
}
