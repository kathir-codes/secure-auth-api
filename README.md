**Secure Auth API**

                 Secure Auth API
                       │
                       ▼
                    Signup
                       ↓
                DTO Validation
                       ↓
                    Signin
                       ↓
              JWT Authentication
                       ↓
                CRUD Operations
                       │
          ┌────────────┼────────────┐
          ↓            ↓            ↓
         GET          POST         PUT
      (Retrieve)     (Create)     (Update)
                       │
                       ↓
                      PATCH
                 (Partial Update)
                       │
                       ↓
                     DELETE
                    (Remove)
                       │
                       ↓
                Forgot Password
                       ↓
                Reset Password
