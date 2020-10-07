package util

func StringSliceToSet(in []string) []string {

	var out []string
	set := make(map[string]struct{})
	for _, v := range in {
		if _, ok := set[v]; !ok {
			out = append(out, v)
		}
		set[v] = struct{}{}
	}
	return out
}

func StringSliceContains(s []string, search string) bool {

	for _, v := range s {
		if v == search {
			return true
		}
	}
	return false
}
