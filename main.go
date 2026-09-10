package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type Student struct {
	ID       int    `json:"id"`
	FullName string `json:"full_name"`
	Class    string `json:"class"`
	Age      int    `json:"age"`
	Email    string `json:"email"`
	UserID   int    `json:"user_id"`
}

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var students []Student
var users []User

var tokens = make(map[string]int)

var nextStudentID = 1
var nextUserID = 1

func sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(data)

	if err != nil {
		fmt.Println("Error:", err)
	}
}

func sendError(w http.ResponseWriter, message string, status int) {
	data := map[string]string{
		"error": message,
	}

	sendJSON(w, data, status)
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))

	return hex.EncodeToString(hash[:])
}

func findStudentByID(id int) (*Student, error) {
	for i := range students {
		if students[i].ID == id {
			return &students[i], nil
		}
	}

	return nil, errors.New("student not found")
}

func findUserByID(id int) (*User, error) {
	for i := range users {
		if users[i].ID == id {
			return &users[i], nil
		}
	}

	return nil, errors.New("user not found")
}

func getNextStudentID() int {
	id := nextStudentID
	nextStudentID++

	return id
}

func getNextUserID() int {
	id := nextUserID
	nextUserID++

	return id
}

func checkAuth(r *http.Request) (*User, bool) {
	header := r.Header.Get("Authorization")

	if header == "" {
		return nil, false
	}

	parts := strings.Split(header, " ")

	if len(parts) != 2 {
		return nil, false
	}

	if parts[0] != "Bearer" {
		return nil, false
	}

	userID, ok := tokens[parts[1]]

	if !ok {
		return nil, false
	}

	user, err := findUserByID(userID)

	if err != nil {
		return nil, false
	}

	return user, true
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var input RegisterInput

	err := json.NewDecoder(r.Body).Decode(&input)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if input.Email == "" || input.Password == "" {
		sendError(w, "Email и пароль обязательны", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.Email == input.Email {
			sendError(w, "Email уже зарегистрирован", http.StatusConflict)
			return
		}
	}

	user := User{
		ID:           getNextUserID(),
		Email:        input.Email,
		PasswordHash: hashPassword(input.Password),
	}

	users = append(users, user)

	sendJSON(w, user, http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var input LoginInput

	err := json.NewDecoder(r.Body).Decode(&input)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if input.Email == "" || input.Password == "" {
		sendError(w, "Email и пароль обязательны", http.StatusBadRequest)
		return
	}

	passwordHash := hashPassword(input.Password)

	for _, user := range users {
		if user.Email == input.Email && user.PasswordHash == passwordHash {

			token := fmt.Sprintf("token-%d-%s", user.ID, user.Email)

			tokens[token] = user.ID

			sendJSON(w, map[string]string{
				"token": token,
			}, http.StatusOK)

			return
		}
	}

	sendError(w, "Неверный email или пароль", http.StatusUnauthorized)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		sendError(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	user, ok := checkAuth(r)

	if !ok {
		sendError(w, "Нет токена или токен неверный", http.StatusUnauthorized)
		return
	}

	sendJSON(w, user, http.StatusOK)
}

func getStudents(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	sendJSON(w, students, http.StatusOK)
}

func getStudentByID(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	idString := r.PathValue("id")

	id, err := strconv.Atoi(idString)

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	student, err := findStudentByID(id)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusNotFound)
		return
	}

	sendJSON(w, student, http.StatusOK)
}

func createStudent(w http.ResponseWriter, r *http.Request) {
	user, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	var student Student

	err := json.NewDecoder(r.Body).Decode(&student)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if student.FullName == "" ||
		student.Class == "" ||
		student.Age <= 0 ||
		student.Email == "" {

		sendError(w, "Не заполнены обязательные поля", http.StatusBadRequest)
		return
	}

	student.ID = getNextStudentID()
	student.UserID = user.ID

	students = append(students, student)

	sendJSON(w, student, http.StatusCreated)
}

func updateStudent(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	idString := r.PathValue("id")

	id, err := strconv.Atoi(idString)

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	student, err := findStudentByID(id)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusNotFound)
		return
	}

	var newStudent Student

	err = json.NewDecoder(r.Body).Decode(&newStudent)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if newStudent.FullName == "" ||
		newStudent.Class == "" ||
		newStudent.Age <= 0 ||
		newStudent.Email == "" {

		sendError(w, "Не заполнены обязательные поля", http.StatusBadRequest)
		return
	}

	newStudent.ID = student.ID
	newStudent.UserID = student.UserID

	*student = newStudent

	sendJSON(w, student, http.StatusOK)
}

func deleteStudent(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	idString := r.PathValue("id")

	id, err := strconv.Atoi(idString)

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findStudentByID(id)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusNotFound)
		return
	}

	index := -1

	for i := range students {
		if students[i].ID == id {
			index = i
			break
		}
	}

	students = append(students[:index], students[index+1:]...)

	sendJSON(w, map[string]string{
		"message": "Ученик удален",
	}, http.StatusOK)
}

func main() {
	http.HandleFunc("POST /auth/register", registerHandler)
	http.HandleFunc("POST /auth/login", loginHandler)

	http.HandleFunc("GET /me", meHandler)

	http.HandleFunc("GET /students", getStudents)
	http.HandleFunc("POST /students", createStudent)

	http.HandleFunc("GET /students/{id}", getStudentByID)
	http.HandleFunc("PUT /students/{id}", updateStudent)
	http.HandleFunc("PATCH /students/{id}", updateStudent)
	http.HandleFunc("DELETE /students/{id}", deleteStudent)

	fmt.Println("SchoolHub server started on http://localhost:8080")

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println("Server error:", err)
	}
}
