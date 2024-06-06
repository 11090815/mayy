package utils

import "sync"

type Set struct {
	items map[interface{}]struct{}
	mutex *sync.RWMutex
}

func NewSet() *Set {
	return &Set{
		items: make(map[interface{}]struct{}),
		mutex: &sync.RWMutex{},
	}
}

func (s *Set) Add(item interface{}) {
	s.mutex.Lock()
	s.items[item] = struct{}{}
	s.mutex.Unlock()
}

func (s *Set) Exists(item interface{}) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.items[item]
	return exists
}

func (s *Set) Size() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.items)
}

func (s *Set) ToArray() []interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	array := make([]interface{}, len(s.items))
	i := 0
	for item := range s.items {
		array[i] = item
		i++
	}
	return array
}

func (s *Set) Remove(item interface{}) {
	s.mutex.Lock()
	delete(s.items, item)
	s.mutex.Unlock()
}

func (s *Set) Clear() {
	s.mutex.Lock()
	s.items = make(map[interface{}]struct{})
	s.mutex.Unlock()
}
