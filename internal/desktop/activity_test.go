package desktop

import "testing"

func TestActivityWrapAndClearDoNotReuseCursor(t *testing.T) {
	a := new(App)
	for i := 0; i < activityLimit+7; i++ {
		a.activity.record("guest", "TCP", "192.0.2.3:443")
	}
	all := a.ActivitySince(0)
	if len(all) != activityLimit || all[0].ID != 8 || all[len(all)-1].ID != activityLimit+7 {
		t.Fatal("wrong history window")
	}
	id := a.ClearActivity()
	if len(a.ActivitySince(0)) != 0 {
		t.Fatal("clear left entries")
	}
	a.activity.record("other", "UDP", "192.0.2.4:123")
	tail := a.ActivitySince(id)
	if len(tail) != 1 || tail[0].VM != "other" || tail[0].ID != id+1 {
		t.Fatalf("tail %+v", tail)
	}
}
