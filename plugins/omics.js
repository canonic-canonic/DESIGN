/**
 * OMICS Plugin for TALK — Live Multi-Omic Intelligence
 * inherits: canonic-shop/CHAT/
 *
 * Queries NCBI E-utilities (GEO, ClinVar) and PharmGKB for live omic context.
 * Extracts gene symbols, rsIDs, GEO accessions from user queries.
 * Injects live evidence into TALK system prompt as LIVE_OMICS_CONTEXT.
 *
 * All API endpoints match governance declarations in OMICSCHAT.md Data Sources.
 * Entity detection is runtime-only; governance declares the data contract.
 *
 * Usage: Loaded by talk.js when CANON.json declares `"omics": true`.
 */

const OMICS = {
    name: 'omics',

    // API endpoints — proxied through Cloudflare Workers (declared in OMICSCHAT.md Data Sources)
    EUTILS: 'https://api.canonic.org/omics/ncbi',
    PHARMGKB: 'https://api.canonic.org/omics/pharmgkb',

    CACHE_TTL: 60 * 60 * 1000, // 1 hour

    // State
    chat: null,
    lastContext: null,

    // Clinically significant genes — triggers live API lookups.
    // Oncology, pharmacogenomics, DNA repair, hematology, signal transduction.
    GENES: new Set([
        'BRCA1','BRCA2','TP53','EGFR','KRAS','NRAS','BRAF','PIK3CA','PTEN','APC',
        'RB1','MYC','ERBB2','HER2','ALK','ROS1','RET','MET',
        'FGFR1','FGFR2','FGFR3','FGFR4','CDK4','CDK6','ESR1','AR',
        'CD274','MSH2','MSH6','MLH1','PMS2','EPCAM','ATM','PALB2','CHEK2',
        'RAD51C','RAD51D','NBN','CDH1','STK11','SMAD4','MUTYH',
        'AKT1','AKT2','AKT3','MTOR','JAK2','JAK1','STAT3','STAT5',
        'IDH1','IDH2','NPM1','FLT3','DNMT3A','TET2','ASXL1','EZH2',
        'SF3B1','SRSF2','U2AF1','WT1','NF1','NF2','TSC1','TSC2','VHL',
        'CTNNB1','NOTCH1','TERT','ARID1A','ARID1B','KMT2A','KMT2D',
        'CREBBP','EP300','BCOR','CIC','DICER1','PTCH1','SUFU','SMO',
        'HRAS','MAP2K1','MAP2K2','CALR','MPL',
        'CYP2D6','CYP2C19','CYP2C9','CYP3A4','CYP3A5','CYP1A2',
        'DPYD','UGT1A1','TPMT','NUDT15','SLCO1B1','ABCB1','VKORC1',
        'G6PD','NAT2','GSTP1','MTHFR','COMT','OPRM1'
    ]),

    // Pharmacogenes — subset that triggers PharmGKB lookups
    PHARMGENES: new Set([
        'CYP2D6','CYP2C19','CYP2C9','CYP3A4','CYP3A5','CYP1A2',
        'DPYD','UGT1A1','TPMT','NUDT15','SLCO1B1','ABCB1','VKORC1',
        'G6PD','NAT2','GSTP1','MTHFR','COMT','OPRM1'
    ]),

    init(chat) {
        this.chat = chat;
    },

    // ── Entity Extraction ──────────────────────────────────────────

    extract(text) {
        var entities = { genes: [], rsids: [], geos: [], clinvars: [] };
        var upper = text.toUpperCase();

        // Gene symbols — scan for uppercase tokens, check against curated set
        var seen = {};
        var words = upper.match(/\b[A-Z][A-Z0-9]{1,9}\b/g) || [];
        for (var i = 0; i < words.length; i++) {
            if (this.GENES.has(words[i]) && !seen[words[i]]) {
                seen[words[i]] = true;
                entities.genes.push(words[i]);
            }
        }

        // PD-L1 special case (hyphenated)
        if (/\bPD-?L1\b/i.test(text) && !seen['CD274']) {
            entities.genes.push('CD274');
        }

        // HER2 → ERBB2 normalization
        if (seen['HER2'] && !seen['ERBB2']) {
            entities.genes.push('ERBB2');
        }

        // rsIDs (variant identifiers)
        var rsMatches = text.match(/\brs\d{3,12}\b/gi) || [];
        for (var j = 0; j < rsMatches.length; j++) {
            entities.rsids.push(rsMatches[j].toLowerCase());
        }

        // GEO accessions
        var geoMatches = text.match(/\bGSE\d{3,8}\b/gi) || [];
        for (var k = 0; k < geoMatches.length; k++) {
            entities.geos.push(geoMatches[k].toUpperCase());
        }

        // ClinVar variation IDs
        var cvMatches = text.match(/\bVCV\d{6,12}\b/gi) || [];
        for (var l = 0; l < cvMatches.length; l++) {
            entities.clinvars.push(cvMatches[l].toUpperCase());
        }

        return entities;
    },

    hasEntities(e) {
        return e.genes.length > 0 || e.rsids.length > 0 || e.geos.length > 0 || e.clinvars.length > 0;
    },

    // ── Cache (follows TRIALS pattern) ─────────────────────────────

    getCache(key) {
        try {
            var cached = JSON.parse(localStorage.getItem(key));
            if (cached && Date.now() - cached.ts < this.CACHE_TTL) return cached.data;
        } catch {}
        return null;
    },

    setCache(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify({ ts: Date.now(), data: data }));
        } catch {}
    },

    // ── NCBI GEO: gene expression datasets ─────────────────────────

    async fetchGEO(gene) {
        var key = 'omics:geo:' + gene;
        var cached = this.getCache(key);
        if (cached) return cached;

        try {
            var searchUrl = this.EUTILS + '/esearch.fcgi?db=gds&term=' +
                encodeURIComponent(gene) + '%5BGene+Name%5D+AND+Expression+profiling&retmax=3&retmode=json';
            var searchRes = await fetch(searchUrl);
            if (!searchRes.ok) return null;
            var searchData = await searchRes.json();

            var ids = (searchData.esearchresult && searchData.esearchresult.idlist || []).slice(0, 3);
            if (!ids.length) return null;

            var summaryUrl = this.EUTILS + '/esummary.fcgi?db=gds&id=' + ids.join(',') + '&retmode=json';
            var summaryRes = await fetch(summaryUrl);
            if (!summaryRes.ok) return null;
            var summaryData = await summaryRes.json();

            var results = [];
            for (var i = 0; i < ids.length; i++) {
                var doc = summaryData.result && summaryData.result[ids[i]];
                if (!doc) continue;
                results.push({
                    accession: doc.accession || ('GDS' + ids[i]),
                    title: doc.title || '',
                    summary: (doc.summary || '').slice(0, 200),
                    samples: doc.n_samples || 0,
                    taxon: doc.taxon || ''
                });
            }

            this.setCache(key, results);
            return results;
        } catch (e) {
            console.warn('[OMICS] GEO fetch error:', e);
            return null;
        }
    },

    // ── NCBI GEO: lookup by accession ───────────────────────────────

    async fetchGEODataset(accession) {
        var key = 'omics:geo-ds:' + accession;
        var cached = this.getCache(key);
        if (cached) return cached;

        try {
            var searchUrl = this.EUTILS + '/esearch.fcgi?db=gds&term=' +
                encodeURIComponent(accession) + '%5BAccession%5D&retmax=1&retmode=json';
            var searchRes = await fetch(searchUrl);
            if (!searchRes.ok) return null;
            var searchData = await searchRes.json();

            var ids = (searchData.esearchresult && searchData.esearchresult.idlist || []).slice(0, 1);
            if (!ids.length) return null;

            var summaryUrl = this.EUTILS + '/esummary.fcgi?db=gds&id=' + ids[0] + '&retmode=json';
            var summaryRes = await fetch(summaryUrl);
            if (!summaryRes.ok) return null;
            var summaryData = await summaryRes.json();

            var doc = summaryData.result && summaryData.result[ids[0]];
            if (!doc) return null;

            var result = {
                accession: doc.accession || accession,
                title: doc.title || '',
                summary: (doc.summary || '').slice(0, 300),
                samples: doc.n_samples || 0,
                taxon: doc.taxon || ''
            };

            this.setCache(key, result);
            return result;
        } catch (e) {
            console.warn('[OMICS] GEO dataset fetch error:', e);
            return null;
        }
    },

    // ── NCBI ClinVar: variant classification ────────────────────────

    async fetchClinVar(variant) {
        var key = 'omics:clinvar:' + variant;
        var cached = this.getCache(key);
        if (cached) return cached;

        try {
            var searchUrl = this.EUTILS + '/esearch.fcgi?db=clinvar&term=' +
                encodeURIComponent(variant) + '&retmax=3&retmode=json';
            var searchRes = await fetch(searchUrl);
            if (!searchRes.ok) return null;
            var searchData = await searchRes.json();

            var ids = (searchData.esearchresult && searchData.esearchresult.idlist || []).slice(0, 3);
            if (!ids.length) return null;

            var summaryUrl = this.EUTILS + '/esummary.fcgi?db=clinvar&id=' + ids.join(',') + '&retmode=json';
            var summaryRes = await fetch(summaryUrl);
            if (!summaryRes.ok) return null;
            var summaryData = await summaryRes.json();

            var results = [];
            for (var i = 0; i < ids.length; i++) {
                var doc = summaryData.result && summaryData.result[ids[i]];
                if (!doc) continue;
                var sig = doc.clinical_significance;
                if (sig && typeof sig === 'object') sig = sig.description || '';
                results.push({
                    uid: ids[i],
                    title: doc.title || '',
                    clinical_significance: sig || '',
                    gene_sort: doc.gene_sort || '',
                    accession: doc.accession || ''
                });
            }

            this.setCache(key, results);
            return results;
        } catch (e) {
            console.warn('[OMICS] ClinVar fetch error:', e);
            return null;
        }
    },

    // ── ClinVar: pathogenic variants by gene ────────────────────────

    async fetchClinVarByGene(gene) {
        var key = 'omics:clinvar-gene:' + gene;
        var cached = this.getCache(key);
        if (cached) return cached;

        try {
            var searchUrl = this.EUTILS + '/esearch.fcgi?db=clinvar&term=' +
                encodeURIComponent(gene) + '%5Bgene%5D+AND+pathogenic%5Bclinical_significance%5D&retmax=5&retmode=json';
            var searchRes = await fetch(searchUrl);
            if (!searchRes.ok) return null;
            var searchData = await searchRes.json();

            var ids = (searchData.esearchresult && searchData.esearchresult.idlist || []).slice(0, 5);
            if (!ids.length) return null;

            var summaryUrl = this.EUTILS + '/esummary.fcgi?db=clinvar&id=' + ids.join(',') + '&retmode=json';
            var summaryRes = await fetch(summaryUrl);
            if (!summaryRes.ok) return null;
            var summaryData = await summaryRes.json();

            var results = [];
            for (var i = 0; i < ids.length; i++) {
                var doc = summaryData.result && summaryData.result[ids[i]];
                if (!doc) continue;
                var sig = doc.clinical_significance;
                if (sig && typeof sig === 'object') sig = sig.description || '';
                results.push({
                    uid: ids[i],
                    title: doc.title || '',
                    clinical_significance: sig || '',
                    accession: doc.accession || ''
                });
            }

            this.setCache(key, results);
            return results;
        } catch (e) {
            console.warn('[OMICS] ClinVar gene fetch error:', e);
            return null;
        }
    },

    // ── PharmGKB: drug-gene interactions ────────────────────────────

    async fetchPharmGKB(gene) {
        var key = 'omics:pharmgkb:' + gene;
        var cached = this.getCache(key);
        if (cached) return cached;

        try {
            var url = this.PHARMGKB + '/clinicalAnnotation?location.genes.symbol=' + encodeURIComponent(gene);
            var res = await fetch(url);
            if (!res.ok) return null;
            var data = await res.json();

            var list = (data.data || []).slice(0, 5);
            var annotations = [];
            for (var i = 0; i < list.length; i++) {
                var a = list[i];
                annotations.push({
                    id: a.id || '',
                    gene: gene,
                    drug: (a.relatedChemicals || []).map(function(c) { return c.name; }).join(', ') || '',
                    phenotype: (a.phenotypes || []).map(function(p) { return p.name; }).join(', ') || '',
                    level: a.level || ''
                });
            }

            this.setCache(key, annotations);
            return annotations;
        } catch (e) {
            console.warn('[OMICS] PharmGKB fetch error:', e);
            return null;
        }
    },

    // ── Aggregate: fetch all context for extracted entities ─────────

    async fetchContext(entities) {
        var context = {
            source: 'OMICS Plugin (NCBI E-utilities, PharmGKB)',
            generatedAt: new Date().toISOString(),
            entities: entities,
            geo: [],
            clinvar: [],
            pharmgkb: []
        };

        var self = this;
        var promises = [];

        // GEO: gene expression datasets by gene name (max 3 genes)
        var geneSlice = entities.genes.slice(0, 3);
        for (var i = 0; i < geneSlice.length; i++) {
            (function(gene) {
                promises.push(
                    self.fetchGEO(gene).then(function(r) { if (r) context.geo = context.geo.concat(r); })
                );
            })(geneSlice[i]);
        }

        // GEO: dataset by accession (max 3)
        var geoSlice = entities.geos.slice(0, 3);
        for (var j = 0; j < geoSlice.length; j++) {
            (function(acc) {
                promises.push(
                    self.fetchGEODataset(acc).then(function(r) { if (r) context.geo.push(r); })
                );
            })(geoSlice[j]);
        }

        // ClinVar: by rsID (max 3)
        var rsSlice = entities.rsids.slice(0, 3);
        for (var k = 0; k < rsSlice.length; k++) {
            (function(rsid) {
                promises.push(
                    self.fetchClinVar(rsid).then(function(r) { if (r) context.clinvar = context.clinvar.concat(r); })
                );
            })(rsSlice[k]);
        }

        // ClinVar: pathogenic variants by gene (max 2 genes)
        var geneCV = entities.genes.slice(0, 2);
        for (var l = 0; l < geneCV.length; l++) {
            (function(gene) {
                promises.push(
                    self.fetchClinVarByGene(gene).then(function(r) { if (r) context.clinvar = context.clinvar.concat(r); })
                );
            })(geneCV[l]);
        }

        // ClinVar: by VCV accession (max 3)
        var vcvSlice = entities.clinvars.slice(0, 3);
        for (var m = 0; m < vcvSlice.length; m++) {
            (function(vcv) {
                promises.push(
                    self.fetchClinVar(vcv).then(function(r) { if (r) context.clinvar = context.clinvar.concat(r); })
                );
            })(vcvSlice[m]);
        }

        // PharmGKB: drug-gene interactions (pharmacogenes only)
        for (var n = 0; n < geneSlice.length; n++) {
            (function(gene) {
                if (self.PHARMGENES.has(gene)) {
                    promises.push(
                        self.fetchPharmGKB(gene).then(function(r) { if (r) context.pharmgkb = context.pharmgkb.concat(r); })
                    );
                }
            })(geneSlice[n]);
        }

        // Await all — fail-closed per promise
        await Promise.allSettled(promises);

        // Deduplicate GEO
        var seenGeo = {};
        context.geo = context.geo.filter(function(g) {
            if (seenGeo[g.accession]) return false;
            seenGeo[g.accession] = true;
            return true;
        });

        // Deduplicate ClinVar
        var seenCV = {};
        context.clinvar = context.clinvar.filter(function(c) {
            var k = c.uid || c.accession;
            if (seenCV[k]) return false;
            seenCV[k] = true;
            return true;
        });

        return context;
    },

    // ── Compact context for system prompt injection ─────────────────

    context() {
        if (!this.lastContext) return null;
        var c = this.lastContext;
        return {
            source: c.source,
            generatedAt: c.generatedAt,
            entities: c.entities,
            geo: c.geo.slice(0, 5).map(function(g) {
                return { accession: g.accession, title: g.title, samples: g.samples };
            }),
            clinvar: c.clinvar.slice(0, 5).map(function(v) {
                return { accession: v.accession, title: v.title, significance: v.clinical_significance };
            }),
            pharmgkb: c.pharmgkb.slice(0, 5).map(function(a) {
                return { gene: a.gene, drug: a.drug, level: a.level };
            })
        };
    },

    // ── Plugin Hooks ────────────────────────────────────────────────

    hooks: {
        async beforeSend(data) {
            try {
                var entities = OMICS.extract(data.text);

                if (OMICS.hasEntities(entities)) {
                    var ctx = await OMICS.fetchContext(entities);
                    OMICS.lastContext = ctx;
                    data.config.omics = OMICS.context();
                } else if (OMICS.lastContext) {
                    // Carry forward last context for follow-up questions
                    data.config.omics = OMICS.context();
                }
            } catch (e) {
                console.warn('[OMICS] beforeSend error:', e);
            }
            return data;
        },

        afterReceive(data) {
            try {
                var reply = data.reply || '';
                var hasTier = /\[(GOLD|SILVER|BRONZE)\]/i.test(reply);
                var hasFindings = OMICS.lastContext &&
                    (OMICS.lastContext.clinvar.length > 0 || OMICS.lastContext.geo.length > 0);

                // Evidence tier validation: the system prompt requires GOLD/SILVER/BRONZE
                // for every finding. This is a soft check — the model self-corrects.
                if (!hasTier && hasFindings) {
                    console.info('[OMICS] Response has live findings but no evidence tier declaration');
                }
            } catch (e) {
                console.warn('[OMICS] afterReceive error:', e);
            }
            return data;
        }
    }
};

// Expose plugin globally for TALK's governed plugin loader.
try { if (typeof window !== 'undefined') window.OMICS = OMICS; } catch {}
