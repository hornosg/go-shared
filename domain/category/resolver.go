// Package category provides deterministic normalization of a product's raw category
// string (VTEX path, MercadoLibre EN constant, uppercase word, or kebab slug) into a
// canonical kebab-case category slug.
//
// It is the twin of domain/businesstype (ADR-005 §5): a single source of truth for the
// category-slug taxonomy, consumed by both webdata-service (ingestion) and pim-service
// (backfill + refresh). See ADR-007.
//
// Precedence (resolved by the caller, ADR-007 §2):
//
//	override table (DB) > ResolveCategorySlug (this package) > "sin-clasificar"
//
// This package is deterministic and DB-free: same raw input always yields the same slug.
// It does NOT validate the result against the declared template vocabulary; mismatches
// (e.g. leaf "Cervezas" -> "cervezas" while the template declares "cervezas-vinos") are
// corrected by the override table, not here.
package category

import (
	"regexp"
	"strings"
)

// Unclassified is the explicit catch-all slug. The resolver never returns it (it always
// produces a best-effort kebab slug for any non-empty input); callers assign it when the
// raw category is empty/whitespace, so unclassified products stay visible and measurable
// rather than NULL (ADR-007 §2).
const Unclassified = "sin-clasificar"

// enConstantToSlug maps MercadoLibre EN constants (domain_id minus the "MLA-" prefix,
// e.g. "BEERS", "SOFT_DRINKS") to the declared kebab slug. Only HIGH-CONFIDENCE,
// unambiguous mappings live here; ambiguous or low-volume constants fall through to
// slugify() and are corrected via the override table.
//
// Keys are the raw constants as they appear in global_products.category (UPPER_SNAKE).
var enConstantToSlug = map[string]string{
	// Bebidas
	"BEERS":          "cervezas-vinos",
	"WINES":          "vinos-tintos",
	"SOFT_DRINKS":    "gaseosas-aguas",
	"MINERAL_WATERS": "gaseosas-aguas",
	"JUICES":         "jugos-polvos",
	"APERITIFS":      "aperitivos-licores",
	// Lácteos (taxonomía: lácteos en almacén)
	"MILK":                  "lacteos",
	"YOGURTS":               "lacteos",
	"BUTTER":                "quesos-manteca",
	"HARD_AND_SOFT_CHEESES": "quesos-manteca",
	// Almacén seco / granos
	"RICE":                          "arroz-legumbres",
	"LENTILS":                       "arroz-legumbres",
	"FLOUR":                         "harinas-premezclas",
	"PASTAS":                        "pastas-secas",
	"COOKING_OILS":                  "aceites-vinagres",
	"VINEGARS":                      "aceites-vinagres",
	"OATMEAL":                       "harinas-premezclas",
	"YERBA_MATE":                    "almacen-seco",
	"GROUND_AND_WHOLE_BEANS_COFFEE": "almacen-seco",
	"TEA":                           "almacen-seco",
	"SUGAR":                         "almacen-seco",
	"SALT":                          "almacen-seco",
	"CORN_KERNELS":                  "almacen-seco",
	"CANNED_AND_PRESERVED_FOOD":     "conservas-enlatados",
	"SAUCES_AND_DRESSINGS":          "conservas-enlatados",
	"JAMS":                          "dulce-leche-reposteria",
	// Galletitas / golosinas / snacks
	"COOKIES":      "galletitas-dulces",
	"CANDIES":      "golosinas",
	"CHOCOLATES":   "chocolates",
	"SALTY_SNACKS": "snacks-salados-alm",
	"PEANUTS":      "snacks-salados-alm",
	// Panadería envasada
	"BREADS": "pan-envasado",
	// Fiambres
	"COLD_CUTS": "fiambres-embutidos",
	"CASINGS":   "fiambres-embutidos",
	// Limpieza
	"BLEACHES":                                "lavandina-desinfectantes",
	"DISHWASHING_DETERGENTS":                  "detergentes-jabones",
	"LAUNDRY_DETERGENTS":                      "detergentes-jabones",
	"FABRIC_SOFTENERS":                        "detergentes-jabones",
	"MULTIPURPOSE_CLEANERS_AND_DISINFECTANTS": "lavandina-desinfectantes",
	"FLOOR_DEODORIZERS":                       "lavandina-desinfectantes",
	"AIR_FRESHENERS":                          "desodorantes-ambientales",
	"CLEANING_SPONGES":                        "accesorios-limpieza",
	// Papelería de hogar
	"TOILET_PAPERS":        "papel-higiene",
	"KITCHEN_PAPER_TOWELS": "papel-higiene",
	"PAPER_NAPKINS":        "papel-higiene",
	// Higiene / perfumería
	"HAIR_SHAMPOOS_AND_CONDITIONERS": "shampoo-acondicionador",
	"DEODORANTS":                     "jabones-desodorantes",
	"BAR_SOAPS":                      "jabones-desodorantes",
	"LIQUID_HAND_AND_BODY_SOAPS":     "jabones-desodorantes",
	"TOOTHPASTES":                    "cuidado-bucal",
	"TOOTHBRUSHES":                   "cuidado-bucal",
	// Bebé
	"DISPOSABLE_BABY_DIAPERS": "panales",
	"WET_BABY_WIPES":          "cuidado-bebe",
}

// slugAlias colapsa un slug-leaf (producido por slugify de la categoría VTEX) al slug
// DECLARADO por los templates del Quickstart, cuando difieren (ADR-007 §2). Es el segundo
// nivel de la resolución determinística: el catálogo usa categorías VTEX finas (cientos de
// hojas) que los templates agrupan con nombres curados. Cada alias apunta al slug declarado
// del template DOMINANTE de ese tipo de producto (el business_type del producto decide a qué
// template matchea en el refresh). Curado contra el worklist del dry-run; lo no mapeado
// conserva su slug-leaf (no rompe nada, sólo no llena una categoría declarada).
//
// Mantener ordenado por rubro. Sólo mapeos de ALTA CONFIANZA; lo ambiguo se deja sin alias.
var slugAlias = map[string]string{
	// --- Congelados: leaf -> path VTEX declarado (fix de regresión: la normalización a leaf
	//     rompería el match exacto que hoy hace andar congelados) ---
	"helados-y-postres":             "/Congelados/Helados y postres/",
	"hamburguesas-y-medallones":     "/Congelados/Hamburguesas y medallones/",
	"nuggets-y-rebozados":           "/Congelados/Nuggets y rebozados/",
	"comidas-y-panificados":         "/Congelados/Comidas y panificados/",
	"frutas-y-vegetales-congelados": "/Congelados/Frutas y vegetales congelados/",
	"papas":                         "/Congelados/Papas/",
	"pescados-y-mariscos":           "/Congelados/Pescados y mariscos/",
	"pollo":                         "/Congelados/Pollo/",

	// --- Bebidas con alcohol (almacén/vinoteca) ---
	"cervezas":               "cervezas-vinos",
	"vinos-finos":            "vinos-tintos",
	"vino-tinto":             "vinos-tintos",
	"champagne-vino-espu":    "espumantes",
	"sidras":                 "espumantes",
	"aperitivos-con-alcohol": "aperitivos-licores",
	"licores":                "aperitivos-licores",

	// --- Lácteos (almacén) ---
	"yogures-enteros":               "lacteos",
	"yogures-descremados":           "lacteos",
	"yogur-en-vasos":                "lacteos",
	"quesos-cremas-y-untables":      "quesos-manteca",
	"quesos-duros-y-semi-duros":     "quesos-manteca",
	"quesos-cremosos-y-mozzarellas": "quesos-manteca",
	"quesos-trozados":               "quesos-manteca",

	// --- Almacén seco / infusiones / aceites ---
	"hierbas-secas-y-especias":     "almacen-seco",
	"especias-y-condimentos":       "almacen-seco",
	"saborizadores":                "almacen-seco",
	"yerba":                        "almacen-seco",
	"te":                           "almacen-seco",
	"cafe-instantaneo":             "almacen-seco",
	"capsulas-de-cafe":             "almacen-seco",
	"sal":                          "almacen-seco",
	"edulcorante":                  "almacen-seco",
	"aceites-de-oliva":             "aceites-vinagres",
	"aceite-de-oliva":              "aceites-vinagres",
	"arroz":                        "arroz-legumbres",
	"legumbres":                    "arroz-legumbres",
	"fideos-largos":                "pastas-secas",
	"fideos-guiseros":              "pastas-secas",
	"fideos-guiseros-y-para-sopas": "pastas-secas",
	"pastas-rellenas":              "pastas-secas",

	// --- Conservas / salsas / dulces (almacén) ---
	"salsas-y-aderezos":                  "conservas-enlatados",
	"conservas-y-salsas-de-tomate":       "conservas-enlatados",
	"aceitunas-y-encurtidos":             "conservas-enlatados",
	"encurtidos-envasados":               "conservas-enlatados",
	"conservas-de-legumbres-y-vegetales": "conservas-enlatados",
	"mermeladas-dulces-y-jaleas":         "dulce-leche-reposteria",
	"mermeladas-y-dulces":                "dulce-leche-reposteria",
	"dulce-de-leche":                     "dulce-leche-reposteria",

	// --- Golosinas / galletitas (almacén) ---
	"caramelos-gomitas-y-chupetines": "golosinas",
	"caramelos":                      "golosinas",
	"bocaditos-confites-y-turrones":  "golosinas",
	"galletas-dulces":                "galletitas-dulces",
	"galletitas-rellenas":            "galletitas-dulces",
	"galletitas-de-agua":             "galletitas-saladas",
	"galletas-de-arroz":              "galletitas-saladas",
	"tostadas-grisines-y-marineras":  "galletitas-saladas",

	// --- Bebidas sin alcohol / panificados (almacén) ---
	"jugos-listos":              "jugos-polvos",
	"jugos-en-polvo":            "jugos-polvos",
	"jugos-concentrados":        "jugos-polvos",
	"aguas-minerales-y-de-mesa": "gaseosas-aguas",
	"aguas-saborizadas":         "gaseosas-aguas",
	"panes-lacteados-y-de-mesa": "pan-envasado",

	// --- Snacks salados (almacén) ---
	"papas-fritas-y-snacks-de-maiz": "snacks-salados-alm",
	"nachos-mani-y-palitos":         "snacks-salados-alm",
	"otros-snacks-salados":          "snacks-salados-alm",
	"productos-copetin":             "snacks-salados-alm",

	// --- Limpieza ---
	"jabones-para-la-ropa":     "detergentes-jabones",
	"suavizantes-para-la-ropa": "detergentes-jabones",
	"lavandinas":               "lavandina-desinfectantes",
	"limpiadores-de-piso":      "lavandina-desinfectantes",
	"limpiadores-liquidos":     "lavandina-desinfectantes",

	// --- Higiene / cuidado capilar / bucal (perfumería dominante) ---
	"shampoos":                 "cuidado-capilar",
	"acondicionadores":         "cuidado-capilar",
	"shampoo-y-acondicionador": "cuidado-capilar",
	"cremas-de-enjuague":       "cuidado-capilar",
	"coloracion":               "cuidado-capilar",
	"pasta-dental":             "cuidado-bucal",
	"cepillos-de-dientes":      "cuidado-bucal",
	"cepillos-dentales":        "cuidado-bucal",
	"enjuagues-bucales":        "cuidado-bucal",
	"toallitas-femeninas":      "higiene-femenina",
	"toallas-femeninas":        "higiene-femenina",
	"protectores-diarios":      "higiene-femenina",
	"proteccion-femenina":      "higiene-femenina",
}

// pathSeparator detects VTEX-style hierarchical categories like
// "/Bebidas/Vinos/Vinos tintos/".
func isPath(raw string) bool {
	return strings.Contains(raw, "/")
}

// enConstantRe matches a MercadoLibre EN constant: all uppercase letters, digits and
// underscores (e.g. "BEERS", "SOFT_DRINKS", "HARD_AND_SOFT_CHEESES").
var enConstantRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func isENConstant(raw string) bool {
	return enConstantRe.MatchString(strings.TrimSpace(raw))
}

// nonSlugChars matches any run of characters that are not lowercase alphanumerics,
// used to collapse separators into a single hyphen.
var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// slugify converts an arbitrary string into a kebab-case slug: lowercased, accent-stripped,
// non-alphanumeric runs collapsed to a single hyphen, trimmed of leading/trailing hyphens.
//
//	"Vinos tintos"        -> "vinos-tintos"
//	"Galletitas dulces"   -> "galletitas-dulces"
//	"BEBIDAS"             -> "bebidas"
func slugify(s string) string {
	s = stripAccents(strings.ToLower(strings.TrimSpace(s)))
	s = nonSlugChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

// leafSegment returns the last non-empty path segment of a VTEX-style category.
//
//	"/Bebidas/Vinos/Vinos tintos/" -> "Vinos tintos"
//	"/Bebidas/Cervezas/"           -> "Cervezas"
func leafSegment(raw string) string {
	segments := strings.Split(raw, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if seg := strings.TrimSpace(segments[i]); seg != "" {
			return seg
		}
	}
	return ""
}

// stripAccents replaces common Spanish accented characters with ASCII. Kept local to the
// package (mirrors domain/businesstype) to avoid coupling with external utilities.
func stripAccents(s string) string {
	r := strings.NewReplacer(
		"á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u",
		"ü", "u", "ñ", "n",
		"Á", "a", "É", "e", "Í", "i", "Ó", "o", "Ú", "u",
		"Ü", "u", "Ñ", "n",
	)
	return r.Replace(s)
}

// ResolveCategorySlug normalizes a product's raw category string into a canonical kebab
// category slug.
//
// Algorithm (deterministic, ADR-007 §2):
//  1. empty/whitespace            -> ("", false)  [caller assigns Unclassified]
//  2. EN constant (UPPER_SNAKE)   -> enConstantToSlug lookup, else slugify(constant)
//  3. VTEX path (contains "/")    -> slugify(leaf segment)
//  4. anything else (word/kebab)  -> slugify(whole string)
//
// Returns (slug, true) for any non-empty input. The override table (DB) takes precedence
// over this result and is the place to fix leaf-vs-declared mismatches (e.g. "Cervezas"
// -> "cervezas" here, but the template declares "cervezas-vinos").
func ResolveCategorySlug(rawCategory string) (string, bool) {
	raw := strings.TrimSpace(rawCategory)
	if raw == "" {
		return "", false
	}

	if isENConstant(raw) {
		if slug, ok := enConstantToSlug[raw]; ok {
			return applyAlias(slug), true
		}
		return applyAlias(slugify(raw)), true
	}

	if isPath(raw) {
		if leaf := leafSegment(raw); leaf != "" {
			return applyAlias(slugify(leaf)), true
		}
	}

	return applyAlias(slugify(raw)), true
}

// applyAlias colapsa un slug-leaf a su slug declarado si hay un alias curado; si no, lo deja igual.
func applyAlias(slug string) string {
	if declared, ok := slugAlias[slug]; ok {
		return declared
	}
	return slug
}
