// Calculateur CVSS v4.0 — couche interface (Vue 3)
// Moteur de calcul : FIRST.ORG, Red Hat et contributeurs — SPDX-License-Identifier: BSD-2-Clause

const SEVERITY = {
  "Aucun":    { key: "none",     label: "Aucune sévérité" },
  "Bas":      { key: "low",      label: "Sévérité faible" },
  "Moyen":    { key: "medium",   label: "Sévérité moyenne" },
  "Haut":     { key: "high",     label: "Sévérité élevée" },
  "Critique": { key: "critical", label: "Sévérité critique" }
};

const LEVELS = {
  "Haut":  { key: "high",   label: "Élevé" },
  "Moyen": { key: "medium", label: "Moyen" },
  "Bas":   { key: "low",    label: "Faible" }
};

const TAB_LABELS = {
  "Métriques de base": "Base",
  "Métriques de menace": "Menace",
  "Métriques environnementales (métriques de base modifiées)": "Environnemental",
  "Métriques environnementales (exigences de sécurité)": "Exigences",
  "Métriques supplémentaires": "Supplémentaires"
};

const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 60;

const app = Vue.createApp({
  data() {
    return {
      cvssConfigData: null,
      vectorInstance: new Vector(),
      cvssInstance: null,
      macroVector: null,
      activeTab: "base",
      showDetails: false,
      theme: "dark",
      gaugeCircumference: GAUGE_CIRCUMFERENCE.toFixed(2),
      tip: { visible: false, text: "", x: 0, y: 0 },
      toast: { visible: false, text: "" },
      toastTimer: null,
      legend: [
        { key: "none",     name: "Aucune",  range: "0,0" },
        { key: "low",      name: "Faible",  range: "0,1 – 3,9" },
        { key: "medium",   name: "Moyenne", range: "4,0 – 6,9" },
        { key: "high",     name: "Élevée",  range: "7,0 – 8,9" },
        { key: "critical", name: "Critique", range: "9,0 – 10,0" }
      ]
    };
  },

  computed: {
    /** Chaîne brute du vecteur CVSS. */
    vector() {
      return this.vectorInstance.raw;
    },
    /** Score numérique courant. */
    score() {
      return this.cvssInstance ? Number(this.cvssInstance.score) : 0;
    },
    /** Clé de sévérité utilisée pour la couleur (none / low / medium / high / critical). */
    severityKey() {
      const raw = this.cvssInstance ? this.cvssInstance.severity : "Aucun";
      return (SEVERITY[raw] || SEVERITY["Aucun"]).key;
    },
    /** Libellé de sévérité affiché. */
    severityLabel() {
      const raw = this.cvssInstance ? this.cvssInstance.severity : "Aucun";
      return (SEVERITY[raw] || SEVERITY["Aucun"]).label;
    },
    /** Nomenclature CVSS (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE). */
    nomenclature() {
      return this.vectorInstance.nomenclature;
    },
    /** Décalage de l'arc de la jauge, proportionnel au score. */
    gaugeOffset() {
      const ratio = Math.min(Math.max(this.score / 10, 0), 1);
      return (GAUGE_CIRCUMFERENCE * (1 - ratio)).toFixed(2);
    },
    /** Détail du macro-vecteur, libellés traduits. */
    breakdown() {
      const raw = this.vectorInstance.severityBreakdown || {};
      return Object.fromEntries(
        Object.entries(raw).map(([label, level]) => [label, (LEVELS[level] || { label: level }).label])
      );
    },
    /** Nombre total de métriques facultatives renseignées. */
    totalChanged() {
      if (!this.cvssConfigData) return 0;
      return Object.values(this.cvssConfigData)
        .reduce((total, data) => total + this.changedCount(data), 0);
    },
    /** Phrase de contexte affichée sous la sévérité. */
    contextLabel() {
      const n = this.totalChanged;
      if (!n) return "métriques de base uniquement";
      return n + (n > 1 ? " métriques facultatives renseignées" : " métrique facultative renseignée");
    }
  },

  methods: {
    /** Charge metrics.json puis initialise le vecteur et le calcul. */
    async loadConfigData() {
      try {
        const response = await fetch("./metrics.json");
        this.cvssConfigData = await response.json();
      } catch (error) {
        console.error("Chargement de la configuration impossible :", error);
      }
    },

    /** Applique une valeur à une métrique et rafraîchit le score. */
    onButton(metric, value) {
      this.vectorInstance.updateMetric(metric, value);
      window.location.hash = this.vector;
      this.updateCVSSInstance();
      this.hideTip();
    },

    /** Recrée l'objet de calcul à partir du vecteur courant. */
    updateCVSSInstance() {
      this.cvssInstance = new CVSS40(this.vectorInstance);
      this.macroVector = this.vectorInstance.equivalentClasses;
    },

    /** Reconstruit les métriques depuis une chaîne de vecteur (lien partagé). */
    setButtonsToVector(vector) {
      if (vector) {
        try {
          this.vectorInstance.updateMetricsFromVectorString(vector);
        } catch (error) {
          console.warn("Vecteur ignoré :", error.message);
          this.vectorInstance = new Vector();
        }
      }
      this.updateCVSSInstance();
    },

    /** Remet toutes les métriques à leur valeur par défaut. */
    onReset() {
      window.location.hash = "";
      this.vectorInstance = new Vector();
      this.updateCVSSInstance();
      this.notify("Métriques réinitialisées");
    },

    /* ---------- Libellés ---------- */

    /** Libellé court d'un onglet. */
    tabLabel(name) {
      return TAB_LABELS[name] || name;
    },

    /** Texte d'une option, sans son code entre parenthèses. */
    label(optionName) {
      return optionName.replace(/\s*\([A-Za-z]+\)\s*$/, "").trim();
    },

    /** Code d'une option (« N » dans « Réseau (N) »). */
    code(optionName) {
      const match = optionName.match(/\(([A-Za-z]+)\)\s*$/);
      return match ? match[1] : "";
    },

    /** Clé de couleur d'un niveau du macro-vecteur. */
    levelKey(levelLabel) {
      const found = Object.values(LEVELS).find(item => item.label === levelLabel);
      return found ? found.key : "medium";
    },

    /** Valeur par défaut d'une métrique. */
    defaultValue(short) {
      const values = Vector.ALL_METRICS[short];
      return values ? values[0] : "X";
    },

    /** Vrai si la métrique est facultative (valeur par défaut « Non défini »). */
    isOptional(metricData) {
      return this.defaultValue(metricData.short) === "X";
    },

    /** Vrai si une métrique facultative a été renseignée. */
    isSet(metricData) {
      return this.isOptional(metricData) && this.vectorInstance.metrics[metricData.short] !== "X";
    },

    /** Nombre de métriques facultatives renseignées dans une catégorie. */
    changedCount(typeData) {
      let count = 0;
      Object.values(typeData.metric_groups).forEach(group => {
        Object.values(group).forEach(metricData => {
          if (this.isSet(metricData)) count += 1;
        });
      });
      return count;
    },

    /* ---------- Presse-papiers ---------- */

    async copy(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (error) {
        const helper = document.createElement("textarea");
        helper.value = text;
        helper.setAttribute("readonly", "");
        helper.style.position = "fixed";
        helper.style.opacity = "0";
        document.body.appendChild(helper);
        helper.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
        document.body.removeChild(helper);
        return ok;
      }
    },

    async copyVector() {
      window.location.hash = this.vector;
      const ok = await this.copy(this.vector);
      this.notify(ok ? "Vecteur copié dans le presse-papiers" : "Copie impossible : sélectionnez le vecteur manuellement");
    },

    async copyLink() {
      window.location.hash = this.vector;
      const ok = await this.copy(window.location.href);
      this.notify(ok ? "Lien de partage copié" : "Copie impossible : copiez l’adresse depuis la barre du navigateur");
    },

    notify(text) {
      this.toast.text = text;
      this.toast.visible = true;
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => { this.toast.visible = false; }, 2600);
    },

    /* ---------- Thème ---------- */

    applyTheme(theme) {
      this.theme = theme;
      document.documentElement.setAttribute("data-theme", theme);
      try { localStorage.setItem("cvss-theme", theme); } catch (e) { /* stockage indisponible */ }
    },

    toggleTheme() {
      this.applyTheme(this.theme === "dark" ? "light" : "dark");
    },

    /* ---------- Infobulles ---------- */

    showTip(event, text) {
      if (!text) return;
      this.tip.text = text;
      this.tip.visible = true;
      const rect = event.currentTarget.getBoundingClientRect();
      this.$nextTick(() => {
        const node = document.querySelector(".tip");
        const width = node ? node.offsetWidth : 320;
        const height = node ? node.offsetHeight : 120;
        const margin = 12;
        let x = rect.left + rect.width / 2 - width / 2;
        x = Math.max(margin, Math.min(x, window.innerWidth - width - margin));
        let y = rect.bottom + 10;
        if (y + height > window.innerHeight - margin) {
          y = Math.max(margin, rect.top - height - 10);
        }
        this.tip.x = Math.round(x);
        this.tip.y = Math.round(y);
      });
    },

    hideTip() {
      this.tip.visible = false;
    }
  },

  async beforeMount() {
    let stored = null;
    try { stored = localStorage.getItem("cvss-theme"); } catch (e) { stored = null; }
    const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    this.applyTheme(stored || (prefersLight ? "light" : "dark"));

    await this.loadConfigData();
    this.setButtonsToVector(decodeURIComponent(window.location.hash.slice(1)));
  },

  mounted() {
    window.addEventListener("hashchange", () => {
      const hash = decodeURIComponent(window.location.hash.slice(1));
      if (hash !== this.vector) this.setButtonsToVector(hash);
    });
    window.addEventListener("scroll", this.hideTip, { passive: true });
    window.addEventListener("keydown", event => {
      if (event.key === "Escape") this.hideTip();
    });
  }
});

app.mount("#app");
