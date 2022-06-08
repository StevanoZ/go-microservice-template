// Code generated by MockGen. DO NOT EDIT.
// Source: db/repository/repository.go

// Package mock_querier is a generated GoMock package.
package mock_querier

import (
	context "context"
	sql "database/sql"
	reflect "reflect"

	querier "github.com/StevanoZ/dv-notification/db/repository"
	gomock "github.com/golang/mock/gomock"
	uuid "github.com/google/uuid"
)

// MockRepository is a mock of Repository interface.
type MockRepository struct {
	ctrl     *gomock.Controller
	recorder *MockRepositoryMockRecorder
}

// MockRepositoryMockRecorder is the mock recorder for MockRepository.
type MockRepositoryMockRecorder struct {
	mock *MockRepository
}

// NewMockRepository creates a new mock instance.
func NewMockRepository(ctrl *gomock.Controller) *MockRepository {
	mock := &MockRepository{ctrl: ctrl}
	mock.recorder = &MockRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepository) EXPECT() *MockRepositoryMockRecorder {
	return m.recorder
}

// CreateErrorMessage mocks base method.
func (m *MockRepository) CreateErrorMessage(ctx context.Context, arg querier.CreateErrorMessageParams) (querier.ErrorMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateErrorMessage", ctx, arg)
	ret0, _ := ret[0].(querier.ErrorMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateErrorMessage indicates an expected call of CreateErrorMessage.
func (mr *MockRepositoryMockRecorder) CreateErrorMessage(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateErrorMessage", reflect.TypeOf((*MockRepository)(nil).CreateErrorMessage), ctx, arg)
}

// CreateUser mocks base method.
func (m *MockRepository) CreateUser(ctx context.Context, arg querier.CreateUserParams) (querier.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, arg)
	ret0, _ := ret[0].(querier.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockRepositoryMockRecorder) CreateUser(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockRepository)(nil).CreateUser), ctx, arg)
}

// CreateUserImage mocks base method.
func (m *MockRepository) CreateUserImage(ctx context.Context, arg querier.CreateUserImageParams) (querier.UserImage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUserImage", ctx, arg)
	ret0, _ := ret[0].(querier.UserImage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUserImage indicates an expected call of CreateUserImage.
func (mr *MockRepositoryMockRecorder) CreateUserImage(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUserImage", reflect.TypeOf((*MockRepository)(nil).CreateUserImage), ctx, arg)
}

// DeleteErrorMessage mocks base method.
func (m *MockRepository) DeleteErrorMessage(ctx context.Context, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteErrorMessage", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteErrorMessage indicates an expected call of DeleteErrorMessage.
func (mr *MockRepositoryMockRecorder) DeleteErrorMessage(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteErrorMessage", reflect.TypeOf((*MockRepository)(nil).DeleteErrorMessage), ctx, id)
}

// DeleteUser mocks base method.
func (m *MockRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockRepositoryMockRecorder) DeleteUser(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockRepository)(nil).DeleteUser), ctx, id)
}

// DeleteUserImage mocks base method.
func (m *MockRepository) DeleteUserImage(ctx context.Context, id uuid.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUserImage", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserImage indicates an expected call of DeleteUserImage.
func (mr *MockRepositoryMockRecorder) DeleteUserImage(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserImage", reflect.TypeOf((*MockRepository)(nil).DeleteUserImage), ctx, id)
}

// FindErrorMessage mocks base method.
func (m *MockRepository) FindErrorMessage(ctx context.Context, arg querier.FindErrorMessageParams) ([]querier.ErrorMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindErrorMessage", ctx, arg)
	ret0, _ := ret[0].([]querier.ErrorMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindErrorMessage indicates an expected call of FindErrorMessage.
func (mr *MockRepositoryMockRecorder) FindErrorMessage(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindErrorMessage", reflect.TypeOf((*MockRepository)(nil).FindErrorMessage), ctx, arg)
}

// FindUserByIdForUpdate mocks base method.
func (m *MockRepository) FindUserByIdForUpdate(ctx context.Context, id uuid.UUID) (querier.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindUserByIdForUpdate", ctx, id)
	ret0, _ := ret[0].(querier.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindUserByIdForUpdate indicates an expected call of FindUserByIdForUpdate.
func (mr *MockRepositoryMockRecorder) FindUserByIdForUpdate(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindUserByIdForUpdate", reflect.TypeOf((*MockRepository)(nil).FindUserByIdForUpdate), ctx, id)
}

// FindUserImageByIdForUpdate mocks base method.
func (m *MockRepository) FindUserImageByIdForUpdate(ctx context.Context, id uuid.UUID) (querier.UserImage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindUserImageByIdForUpdate", ctx, id)
	ret0, _ := ret[0].(querier.UserImage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindUserImageByIdForUpdate indicates an expected call of FindUserImageByIdForUpdate.
func (mr *MockRepositoryMockRecorder) FindUserImageByIdForUpdate(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindUserImageByIdForUpdate", reflect.TypeOf((*MockRepository)(nil).FindUserImageByIdForUpdate), ctx, id)
}

// FindUserMainImageByUserIdForUpdate mocks base method.
func (m *MockRepository) FindUserMainImageByUserIdForUpdate(ctx context.Context, userID uuid.UUID) (querier.UserImage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindUserMainImageByUserIdForUpdate", ctx, userID)
	ret0, _ := ret[0].(querier.UserImage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindUserMainImageByUserIdForUpdate indicates an expected call of FindUserMainImageByUserIdForUpdate.
func (mr *MockRepositoryMockRecorder) FindUserMainImageByUserIdForUpdate(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindUserMainImageByUserIdForUpdate", reflect.TypeOf((*MockRepository)(nil).FindUserMainImageByUserIdForUpdate), ctx, userID)
}

// GetDB mocks base method.
func (m *MockRepository) GetDB() *sql.DB {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDB")
	ret0, _ := ret[0].(*sql.DB)
	return ret0
}

// GetDB indicates an expected call of GetDB.
func (mr *MockRepositoryMockRecorder) GetDB() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDB", reflect.TypeOf((*MockRepository)(nil).GetDB))
}

// UpdateUser mocks base method.
func (m *MockRepository) UpdateUser(ctx context.Context, arg querier.UpdateUserParams) (querier.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", ctx, arg)
	ret0, _ := ret[0].(querier.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockRepositoryMockRecorder) UpdateUser(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockRepository)(nil).UpdateUser), ctx, arg)
}

// UpdateUserImage mocks base method.
func (m *MockRepository) UpdateUserImage(ctx context.Context, arg querier.UpdateUserImageParams) (querier.UserImage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserImage", ctx, arg)
	ret0, _ := ret[0].(querier.UserImage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUserImage indicates an expected call of UpdateUserImage.
func (mr *MockRepositoryMockRecorder) UpdateUserImage(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserImage", reflect.TypeOf((*MockRepository)(nil).UpdateUserImage), ctx, arg)
}

// UpdateUserMainImage mocks base method.
func (m *MockRepository) UpdateUserMainImage(ctx context.Context, arg querier.UpdateUserMainImageParams) (querier.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserMainImage", ctx, arg)
	ret0, _ := ret[0].(querier.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUserMainImage indicates an expected call of UpdateUserMainImage.
func (mr *MockRepositoryMockRecorder) UpdateUserMainImage(ctx, arg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserMainImage", reflect.TypeOf((*MockRepository)(nil).UpdateUserMainImage), ctx, arg)
}

// WithTx mocks base method.
func (m *MockRepository) WithTx(tx *sql.Tx) querier.Querier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithTx", tx)
	ret0, _ := ret[0].(querier.Querier)
	return ret0
}

// WithTx indicates an expected call of WithTx.
func (mr *MockRepositoryMockRecorder) WithTx(tx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithTx", reflect.TypeOf((*MockRepository)(nil).WithTx), tx)
}
