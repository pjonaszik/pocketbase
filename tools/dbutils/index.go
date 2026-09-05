package dbutils

import (
	"regexp"
	"strings"

	"github.com/pocketbase/pocketbase/tools/tokenizer"
)

var (
	indexRegex       = regexp.MustCompile(`(?im)create\s+(unique\s+)?\s*index\s*(if\s+not\s+exists\s+)?(\S*)\s+on\s+(\S*?)\s*\(`)
	indexColumnRegex = regexp.MustCompile(`(?i)^([\s\S]+?)(?:\s+collate\s+([\w]+))?(?:\s+(asc|desc))?$`)
)

// IndexColumn represents a single parsed SQL index column.
type IndexColumn struct {
	Name    string `json:"name"` // identifier or expression
	Collate string `json:"collate"`
	Sort    string `json:"sort"`
}

// Index represents a single parsed SQL CREATE INDEX expression.
type Index struct {
	SchemaName string        `json:"schemaName"`
	IndexName  string        `json:"indexName"`
	TableName  string        `json:"tableName"`
	Where      string        `json:"where"`
	Columns    []IndexColumn `json:"columns"`
	Unique     bool          `json:"unique"`
	Optional   bool          `json:"optional"`
}

// IsValid checks if the current Index contains the minimum required fields to be considered valid.
func (idx Index) IsValid() bool {
	return idx.IndexName != "" && idx.TableName != "" && len(idx.Columns) > 0
}

// Build returns a "CREATE INDEX" SQL string from the current index parts.
//
// Returns empty string if idx.IsValid() is false.
func (idx Index) Build() string {
	if !idx.IsValid() {
		return ""
	}

	var str strings.Builder

	str.WriteString("CREATE ")

	if idx.Unique {
		str.WriteString("UNIQUE ")
	}

	str.WriteString("INDEX ")

	if idx.Optional {
		str.WriteString("IF NOT EXISTS ")
	}

	if idx.SchemaName != "" {
		str.WriteString("`")
		str.WriteString(idx.SchemaName)
		str.WriteString("`.")
	}

	str.WriteString("`")
	str.WriteString(idx.IndexName)
	str.WriteString("` ")

	str.WriteString("ON `")
	str.WriteString(idx.TableName)
	str.WriteString("` (")

	if len(idx.Columns) > 1 {
		str.WriteString("\n  ")
	}

	var hasCol bool
	for _, col := range idx.Columns {
		trimmedColName := strings.TrimSpace(col.Name)
		if trimmedColName == "" {
			continue
		}

		if hasCol {
			str.WriteString(",\n  ")
		}

		if strings.Contains(col.Name, "(") || strings.Contains(col.Name, " ") {
			// most likely an expression
			str.WriteString(trimmedColName)
		} else {
			// regular identifier
			str.WriteString("`")
			str.WriteString(trimmedColName)
			str.WriteString("`")
		}

		if col.Collate != "" {
			str.WriteString(" COLLATE ")
			str.WriteString(col.Collate)
		}

		if col.Sort != "" {
			str.WriteString(" ")
			str.WriteString(strings.ToUpper(col.Sort))
		}

		hasCol = true
	}

	if hasCol && len(idx.Columns) > 1 {
		str.WriteString("\n")
	}

	str.WriteString(")")

	if idx.Where != "" {
		str.WriteString(" WHERE ")
		str.WriteString(idx.Where)
	}

	return str.String()
}

// splitIndexColumnsAndWhere splits the part of a "CREATE INDEX" statement
// starting at the opening "(" of the columns list into the raw columns
// expression and the optional trailing WHERE expression.
//
// Parentheses are matched with a depth counter that ignores anything inside
// single/double/backtick quoted literals, so that parentheses within a column
// expression (ex. json_extract(...)) or a partial-index WHERE predicate
// (ex. col IN ('a','b')) are handled correctly.
func splitIndexColumnsAndWhere(s string) (columns string, where string, ok bool) {
	open := strings.IndexByte(s, '(')
	if open < 0 {
		return "", "", false
	}

	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]

		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}

		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				columns = s[open+1 : i]
				rest := strings.TrimSpace(s[i+1:])
				if len(rest) >= 5 && strings.EqualFold(rest[:5], "where") {
					where = strings.TrimSpace(rest[5:])
				}
				return columns, where, true
			}
		}
	}

	return "", "", false
}

// ParseIndex parses the provided "CREATE INDEX" SQL string into Index struct.
func ParseIndex(createIndexExpr string) Index {
	result := Index{}

	loc := indexRegex.FindStringSubmatchIndex(createIndexExpr)
	if len(loc) != 10 {
		return result
	}
	matches := make([]string, 5)
	for i := 0; i < 5; i++ {
		if loc[2*i] >= 0 {
			matches[i] = createIndexExpr[loc[2*i]:loc[2*i+1]]
		}
	}

	// the columns list starts at the "(" that the regex stops on;
	// scan it with balanced parentheses (honoring quotes) so that
	// parentheses inside a column expression or a WHERE predicate
	// do not confuse the split between the columns and the WHERE clause.
	columnsExpr, whereExpr, ok := splitIndexColumnsAndWhere(createIndexExpr[loc[1]-1:])
	if !ok {
		return result
	}

	trimChars := "`\"'[]\r\n\t\f\v "

	// Unique
	// ---
	result.Unique = strings.TrimSpace(matches[1]) != ""

	// Optional (aka. "IF NOT EXISTS")
	// ---
	result.Optional = strings.TrimSpace(matches[2]) != ""

	// SchemaName and IndexName
	// ---
	nameTk := tokenizer.NewFromString(matches[3])
	nameTk.Separators('.')

	nameParts, _ := nameTk.ScanAll()
	switch len(nameParts) {
	case 1:
		result.IndexName = strings.Trim(nameParts[0], trimChars)
	case 2:
		result.SchemaName = strings.Trim(nameParts[0], trimChars)
		result.IndexName = strings.Trim(nameParts[1], trimChars)
	}

	// TableName
	// ---
	result.TableName = strings.Trim(matches[4], trimChars)

	// Columns
	// ---
	columnsTk := tokenizer.NewFromString(columnsExpr)
	columnsTk.Separators(',')

	rawColumns, _ := columnsTk.ScanAll()

	result.Columns = make([]IndexColumn, 0, len(rawColumns))

	for _, col := range rawColumns {
		colMatches := indexColumnRegex.FindStringSubmatch(col)
		if len(colMatches) != 4 {
			continue
		}

		trimmedName := strings.Trim(colMatches[1], trimChars)
		if trimmedName == "" {
			continue
		}

		result.Columns = append(result.Columns, IndexColumn{
			Name:    trimmedName,
			Collate: strings.TrimSpace(colMatches[2]),
			Sort:    strings.ToUpper(colMatches[3]),
		})
	}

	// WHERE expression
	// ---
	result.Where = strings.TrimSpace(whereExpr)

	return result
}

// FindSingleColumnUniqueIndex returns the first matching single column unique index.
func FindSingleColumnUniqueIndex(indexes []string, column string) (Index, bool) {
	var index Index

	for _, idx := range indexes {
		index := ParseIndex(idx)
		if index.Unique && len(index.Columns) == 1 && strings.EqualFold(index.Columns[0].Name, column) {
			return index, true
		}
	}

	return index, false
}

// Deprecated: Use `_, ok := FindSingleColumnUniqueIndex(indexes, column)` instead.
//
// HasColumnUniqueIndex loosely checks whether the specified column has
// a single column unique index (WHERE statements are ignored).
func HasSingleColumnUniqueIndex(column string, indexes []string) bool {
	_, ok := FindSingleColumnUniqueIndex(indexes, column)
	return ok
}
