package core_test

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// Deleting the root of a self-referential, multi-value, cascade-delete
// relation must not leave a sibling record with a dangling reference to an
// already-deleted record, and must cascade-delete a record whose every
// linked relation was removed by the cascade.
func TestRecordDeleteSelfRefMultiCascade(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	col := core.NewBaseCollection("selfref")
	col.Fields.Add(
		&core.RelationField{
			Name:          "refs",
			MaxSelect:     10,
			CollectionId:  "", // set below to its own id
			CascadeDelete: true,
			Required:      false,
		},
	)
	// self-reference
	if err := app.SaveNoValidate(col); err != nil {
		t.Fatal(err)
	}
	rel := col.Fields.GetByName("refs").(*core.RelationField)
	rel.CollectionId = col.Id
	if err := app.SaveNoValidate(col); err != nil {
		t.Fatal(err)
	}

	mk := func(id string, refs []string) *core.Record {
		r := core.NewRecord(col)
		r.Id = id
		r.Set("refs", refs)
		if err := app.SaveNoValidate(r); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
		return r
	}

	// insertion order fixes the rowid order used by the unordered batch query
	mk("root0000000000", []string{})
	mk("aaaaaaaaaaaaaaa", []string{"root0000000000"})
	mk("bbbbbbbbbbbbbbb", []string{"root0000000000", "aaaaaaaaaaaaaaa"})

	root, err := app.FindRecordById(col, "root0000000000")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(root); err != nil {
		t.Fatal(err)
	}

	remaining, err := app.FindAllRecords(col.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range remaining {
		for _, id := range r.GetStringSlice("refs") {
			if _, err := app.FindRecordById(col, id); err != nil {
				t.Fatalf("record %s has a dangling reference to deleted record %s", r.Id, id)
			}
		}
	}

	if len(remaining) != 0 {
		ids := make([]string, len(remaining))
		for i, r := range remaining {
			ids[i] = r.Id + "(refs=" + join(r.GetStringSlice("refs")) + ")"
		}
		t.Fatalf("expected all records cascade-deleted, %d survived: %v", len(remaining), ids)
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
