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
	"time"
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

type Teacher struct {
	ID       int    `json:"id"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

type Subject struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	TeacherID int   `json:"teacher_id"`
}

type Grade struct {
	ID        int    `json:"id"`
	StudentID int    `json:"student_id"`
	SubjectID int    `json:"subject_id"`
	Value     int    `json:"value"`
	Date      string `json:"date"`
	Comment   string `json:"comment"`
}

type Homework struct {
	ID          int    `json:"id"`
	SubjectID   int    `json:"subject_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IssueDate   string `json:"issue_date"`
	Deadline    string `json:"deadline"`
}

var students []Student
var users []User
var teachers []Teacher
var subjects []Subject
var grades []Grade
var homeworks []Homework

var tokens = make(map[string]int)

var nextStudentID = 1
var nextUserID = 1
var nextTeacherID = 1
var nextSubjectID = 1
var nextGradeID = 1
var nextHomeworkID = 1

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

func findTeacherByID(id int) (*Teacher, error) {
	for i := range teachers {
		if teachers[i].ID == id {
			return &teachers[i], nil
		}
	}

	return nil, errors.New("teacher not found")
}

func findSubjectByID(id int) (*Subject, error) {
	for i := range subjects {
		if subjects[i].ID == id {
			return &subjects[i], nil
		}
	}

	return nil, errors.New("subject not found")
}

func findGradeByID(id int) (*Grade, error) {
	for i := range grades {
		if grades[i].ID == id {
			return &grades[i], nil
		}
	}

	return nil, errors.New("grade not found")
}

func findHomeworkByID(id int) (*Homework, error) {
	for i := range homeworks {
		if homeworks[i].ID == id {
			return &homeworks[i], nil
		}
	}

	return nil, errors.New("homework not found")
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

func getNextTeacherID() int {
	id := nextTeacherID
	nextTeacherID++

	return id
}

func getNextSubjectID() int {
	id := nextSubjectID
	nextSubjectID++

	return id
}

func getNextGradeID() int {
	id := nextGradeID
	nextGradeID++

	return id
}

func getNextHomeworkID() int {
	id := nextHomeworkID
	nextHomeworkID++

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

// =========================
// STUDENTS
// =========================

func getStudents(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	class := r.URL.Query().Get("class")

	if class == "" {
		sendJSON(w, students, http.StatusOK)
		return
	}

	result := []Student{}

	for _, student := range students {
		if student.Class == class {
			result = append(result, student)
		}
	}

	sendJSON(w, result, http.StatusOK)
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

// =========================
// TEACHERS
// =========================

func getTeachers(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	sendJSON(w, teachers, http.StatusOK)
}

func getTeacherByID(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	teacher, err := findTeacherByID(id)

	if err != nil {
		sendError(w, "Учитель не найден", http.StatusNotFound)
		return
	}

	sendJSON(w, teacher, http.StatusOK)
}

func createTeacher(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	var teacher Teacher

	err := json.NewDecoder(r.Body).Decode(&teacher)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if teacher.FullName == "" || teacher.Email == "" {
		sendError(w, "ФИО и email обязательны", http.StatusBadRequest)
		return
	}

	teacher.ID = getNextTeacherID()

	teachers = append(teachers, teacher)

	sendJSON(w, teacher, http.StatusCreated)
}

func updateTeacher(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	teacher, err := findTeacherByID(id)

	if err != nil {
		sendError(w, "Учитель не найден", http.StatusNotFound)
		return
	}

	var newTeacher Teacher

	err = json.NewDecoder(r.Body).Decode(&newTeacher)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if newTeacher.FullName == "" || newTeacher.Email == "" {
		sendError(w, "ФИО и email обязательны", http.StatusBadRequest)
		return
	}

	newTeacher.ID = teacher.ID

	*teacher = newTeacher

	sendJSON(w, teacher, http.StatusOK)
}

func deleteTeacher(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findTeacherByID(id)

	if err != nil {
		sendError(w, "Учитель не найден", http.StatusNotFound)
		return
	}

	index := -1

	for i := range teachers {
		if teachers[i].ID == id {
			index = i
			break
		}
	}

	teachers = append(teachers[:index], teachers[index+1:]...)

	sendJSON(w, map[string]string{
		"message": "Учитель удален",
	}, http.StatusOK)
}

// =========================
// SUBJECTS
// =========================

func getSubjects(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	sendJSON(w, subjects, http.StatusOK)
}

func getSubjectByID(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	subject, err := findSubjectByID(id)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusNotFound)
		return
	}

	sendJSON(w, subject, http.StatusOK)
}

func createSubject(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	var subject Subject

	err := json.NewDecoder(r.Body).Decode(&subject)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if subject.Name == "" {
		sendError(w, "Название предмета обязательно", http.StatusBadRequest)
		return
	}

	_, err = findTeacherByID(subject.TeacherID)

	if err != nil {
		sendError(w, "Учитель не найден", http.StatusBadRequest)
		return
	}

	subject.ID = getNextSubjectID()

	subjects = append(subjects, subject)

	sendJSON(w, subject, http.StatusCreated)
}

func updateSubject(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	subject, err := findSubjectByID(id)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusNotFound)
		return
	}

	var newSubject Subject

	err = json.NewDecoder(r.Body).Decode(&newSubject)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if newSubject.Name == "" {
		sendError(w, "Название предмета обязательно", http.StatusBadRequest)
		return
	}

	_, err = findTeacherByID(newSubject.TeacherID)

	if err != nil {
		sendError(w, "Учитель не найден", http.StatusBadRequest)
		return
	}

	newSubject.ID = subject.ID

	*subject = newSubject

	sendJSON(w, subject, http.StatusOK)
}

func deleteSubject(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findSubjectByID(id)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusNotFound)
		return
	}

	index := -1

	for i := range subjects {
		if subjects[i].ID == id {
			index = i
			break
		}
	}

	subjects = append(subjects[:index], subjects[index+1:]...)

	sendJSON(w, map[string]string{
		"message": "Предмет удален",
	}, http.StatusOK)
}

// =========================
// GRADES
// =========================

func getGrades(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	sendJSON(w, grades, http.StatusOK)
}

func getGradeByID(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	grade, err := findGradeByID(id)

	if err != nil {
		sendError(w, "Оценка не найдена", http.StatusNotFound)
		return
	}

	sendJSON(w, grade, http.StatusOK)
}

func createGrade(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	var grade Grade

	err := json.NewDecoder(r.Body).Decode(&grade)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if grade.Value < 1 || grade.Value > 5 {
		sendError(w, "Оценка должна быть от 1 до 5", http.StatusBadRequest)
		return
	}

	_, err = findStudentByID(grade.StudentID)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusBadRequest)
		return
	}

	_, err = findSubjectByID(grade.SubjectID)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusBadRequest)
		return
	}

	if grade.Date == "" {
		sendError(w, "Дата обязательна", http.StatusBadRequest)
		return
	}

	_, err = time.Parse("2006-01-02", grade.Date)

	if err != nil {
		sendError(w, "Дата должна быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	grade.ID = getNextGradeID()

	grades = append(grades, grade)

	sendJSON(w, grade, http.StatusCreated)
}

func updateGrade(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	grade, err := findGradeByID(id)

	if err != nil {
		sendError(w, "Оценка не найдена", http.StatusNotFound)
		return
	}

	var newGrade Grade

	err = json.NewDecoder(r.Body).Decode(&newGrade)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if newGrade.Value < 1 || newGrade.Value > 5 {
		sendError(w, "Оценка должна быть от 1 до 5", http.StatusBadRequest)
		return
	}

	_, err = findStudentByID(newGrade.StudentID)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusBadRequest)
		return
	}

	_, err = findSubjectByID(newGrade.SubjectID)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusBadRequest)
		return
	}

	if newGrade.Date == "" {
		sendError(w, "Дата обязательна", http.StatusBadRequest)
		return
	}

	_, err = time.Parse("2006-01-02", newGrade.Date)

	if err != nil {
		sendError(w, "Дата должна быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	newGrade.ID = grade.ID

	*grade = newGrade

	sendJSON(w, grade, http.StatusOK)
}

func deleteGrade(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findGradeByID(id)

	if err != nil {
		sendError(w, "Оценка не найдена", http.StatusNotFound)
		return
	}

	index := -1

	for i := range grades {
		if grades[i].ID == id {
			index = i
			break
		}
	}

	grades = append(grades[:index], grades[index+1:]...)

	sendJSON(w, map[string]string{
		"message": "Оценка удалена",
	}, http.StatusOK)
}

// =========================
// STUDENT GRADES
// =========================

func getStudentGrades(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	studentID, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findStudentByID(studentID)

	if err != nil {
		sendError(w, "Ученик не найден", http.StatusNotFound)
		return
	}

	subjectIDString := r.URL.Query().Get("subject_id")

	result := []Grade{}

	for _, grade := range grades {
		if grade.StudentID != studentID {
			continue
		}

		if subjectIDString != "" {
			subjectID, err := strconv.Atoi(subjectIDString)

			if err != nil {
				sendError(w, "Неверный subject_id", http.StatusBadRequest)
				return
			}

			if grade.SubjectID != subjectID {
				continue
			}
		}

		result = append(result, grade)
	}

	sendJSON(w, result, http.StatusOK)
}

// =========================
// HOMEWORK
// =========================

func getHomeworks(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	subjectIDString := r.URL.Query().Get("subject_id")
	overdue := r.URL.Query().Get("overdue")

	var subjectID int

	if subjectIDString != "" {
		var err error

		subjectID, err = strconv.Atoi(subjectIDString)

		if err != nil {
			sendError(w, "Неверный subject_id", http.StatusBadRequest)
			return
		}
	}

	if overdue != "" && overdue != "true" && overdue != "false" {
		sendError(w, "overdue должен быть true или false", http.StatusBadRequest)
		return
	}

	result := []Homework{}

	for _, homework := range homeworks {

		if subjectIDString != "" && homework.SubjectID != subjectID {
			continue
		}

		if overdue == "true" {
			deadline, err := time.Parse("2006-01-02", homework.Deadline)

			if err != nil {
				continue
			}

			today := time.Now()

			if !deadline.Before(today) {
				continue
			}
		}

		result = append(result, homework)
	}

	sendJSON(w, result, http.StatusOK)
}

func getHomeworkByID(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	homework, err := findHomeworkByID(id)

	if err != nil {
		sendError(w, "Домашнее задание не найдено", http.StatusNotFound)
		return
	}

	sendJSON(w, homework, http.StatusOK)
}

func createHomework(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	var homework Homework

	err := json.NewDecoder(r.Body).Decode(&homework)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if homework.Title == "" ||
		homework.IssueDate == "" ||
		homework.Deadline == "" {

		sendError(w, "Название, дата выдачи и дедлайн обязательны", http.StatusBadRequest)
		return
	}

	_, err = findSubjectByID(homework.SubjectID)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusBadRequest)
		return
	}

	issueDate, err := time.Parse("2006-01-02", homework.IssueDate)

	if err != nil {
		sendError(w, "Дата выдачи должна быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	deadline, err := time.Parse("2006-01-02", homework.Deadline)

	if err != nil {
		sendError(w, "Дедлайн должен быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	if deadline.Before(issueDate) {
		sendError(w, "Дедлайн не может быть раньше даты выдачи", http.StatusBadRequest)
		return
	}

	homework.ID = getNextHomeworkID()

	homeworks = append(homeworks, homework)

	sendJSON(w, homework, http.StatusCreated)
}

func updateHomework(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	homework, err := findHomeworkByID(id)

	if err != nil {
		sendError(w, "Домашнее задание не найдено", http.StatusNotFound)
		return
	}

	var newHomework Homework

	err = json.NewDecoder(r.Body).Decode(&newHomework)

	if err != nil {
		sendError(w, "Неверный JSON", http.StatusBadRequest)
		return
	}

	if newHomework.Title == "" ||
		newHomework.IssueDate == "" ||
		newHomework.Deadline == "" {

		sendError(w, "Название, дата выдачи и дедлайн обязательны", http.StatusBadRequest)
		return
	}

	_, err = findSubjectByID(newHomework.SubjectID)

	if err != nil {
		sendError(w, "Предмет не найден", http.StatusBadRequest)
		return
	}

	issueDate, err := time.Parse("2006-01-02", newHomework.IssueDate)

	if err != nil {
		sendError(w, "Дата выдачи должна быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	deadline, err := time.Parse("2006-01-02", newHomework.Deadline)

	if err != nil {
		sendError(w, "Дедлайн должен быть в формате YYYY-MM-DD", http.StatusBadRequest)
		return
	}

	if deadline.Before(issueDate) {
		sendError(w, "Дедлайн не может быть раньше даты выдачи", http.StatusBadRequest)
		return
	}

	newHomework.ID = homework.ID

	*homework = newHomework

	sendJSON(w, homework, http.StatusOK)
}

func deleteHomework(w http.ResponseWriter, r *http.Request) {
	_, ok := checkAuth(r)

	if !ok {
		sendError(w, "Требуется авторизация", http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))

	if err != nil {
		sendError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	_, err = findHomeworkByID(id)

	if err != nil {
		sendError(w, "Домашнее задание не найдено", http.StatusNotFound)
		return
	}

	index := -1

	for i := range homeworks {
		if homeworks[i].ID == id {
			index = i
			break
		}
	}

	homeworks = append(homeworks[:index], homeworks[index+1:]...)

	sendJSON(w, map[string]string{
		"message": "Домашнее задание удалено",
	}, http.StatusOK)
}

func main() {
	http.HandleFunc("POST /auth/register", registerHandler)
	http.HandleFunc("POST /auth/login", loginHandler)

	http.HandleFunc("GET /me", meHandler)

	http.HandleFunc("GET /students", getStudents)
	http.HandleFunc("POST /students", createStudent)

	http.HandleFunc("GET /students/{id}/grades", getStudentGrades)

	http.HandleFunc("GET /students/{id}", getStudentByID)
	http.HandleFunc("PUT /students/{id}", updateStudent)
	http.HandleFunc("PATCH /students/{id}", updateStudent)
	http.HandleFunc("DELETE /students/{id}", deleteStudent)

	http.HandleFunc("GET /teachers", getTeachers)
	http.HandleFunc("POST /teachers", createTeacher)

	http.HandleFunc("GET /teachers/{id}", getTeacherByID)
	http.HandleFunc("PUT /teachers/{id}", updateTeacher)
	http.HandleFunc("PATCH /teachers/{id}", updateTeacher)
	http.HandleFunc("DELETE /teachers/{id}", deleteTeacher)

	http.HandleFunc("GET /subjects", getSubjects)
	http.HandleFunc("POST /subjects", createSubject)

	http.HandleFunc("GET /subjects/{id}", getSubjectByID)
	http.HandleFunc("PUT /subjects/{id}", updateSubject)
	http.HandleFunc("PATCH /subjects/{id}", updateSubject)
	http.HandleFunc("DELETE /subjects/{id}", deleteSubject)

	http.HandleFunc("GET /grades", getGrades)
	http.HandleFunc("POST /grades", createGrade)

	http.HandleFunc("GET /grades/{id}", getGradeByID)
	http.HandleFunc("PUT /grades/{id}", updateGrade)
	http.HandleFunc("PATCH /grades/{id}", updateGrade)
	http.HandleFunc("DELETE /grades/{id}", deleteGrade)

	http.HandleFunc("GET /homework", getHomeworks)
	http.HandleFunc("POST /homework", createHomework)

	http.HandleFunc("GET /homework/{id}", getHomeworkByID)
	http.HandleFunc("PUT /homework/{id}", updateHomework)
	http.HandleFunc("PATCH /homework/{id}", updateHomework)
	http.HandleFunc("DELETE /homework/{id}", deleteHomework)

	fmt.Println("SchoolHub server started on http://localhost:8080")

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println("Server error:", err)
	}
}
