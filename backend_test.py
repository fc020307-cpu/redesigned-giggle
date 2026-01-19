import requests
import sys
import time
import json
from datetime import datetime

class EmailValidatorAPITester:
    def __init__(self, base_url="https://verifymyemail.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.job_id = None
        self.token = None
        self.user_data = None

    def run_test(self, name, method, endpoint, expected_status, data=None, files=None, auth=False):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'} if not files else {}
        
        # Add auth header if needed
        if auth and self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                if files:
                    # Remove Content-Type for file uploads
                    if 'Content-Type' in headers:
                        del headers['Content-Type']
                    response = requests.post(url, files=files, headers=headers)
                else:
                    response = requests.post(url, json=data, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API", "GET", "", 200)

    def test_user_registration(self):
        """Test user registration"""
        timestamp = int(time.time())
        test_user = {
            "name": "Test User",
            "email": f"newuser{timestamp}@test.com",
            "password": "test123"
        }
        
        success, response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data=test_user
        )
        
        if success and 'token' in response:
            self.token = response['token']
            self.user_data = response['user']
            print(f"   User ID: {self.user_data.get('id', 'N/A')}")
            print(f"   User Plan: {self.user_data.get('plan', 'N/A')}")
        
        return success

    def test_user_login(self):
        """Test user login with existing user"""
        if not self.user_data:
            print("❌ No user data available for login test")
            return False
            
        login_data = {
            "email": "newuser@test.com",
            "password": "test123"
        }
        
        success, response = self.run_test(
            "User Login",
            "POST",
            "auth/login",
            200,
            data=login_data
        )
        
        if success and 'token' in response:
            print(f"   Login successful for: {response['user'].get('email', 'N/A')}")
        
        return success

    def test_get_user_profile(self):
        """Test getting user profile"""
        if not self.token:
            print("❌ No token available for profile test")
            return False
            
        success, response = self.run_test(
            "Get User Profile",
            "GET",
            "auth/me",
            200,
            auth=True
        )
        
        if success:
            print(f"   Profile Email: {response.get('email', 'N/A')}")
            print(f"   Verifications Used: {response.get('verifications_used', 0)}")
            print(f"   Verifications Limit: {response.get('verifications_limit', 0)}")
        
        return success

    def test_get_plans(self):
        """Test getting pricing plans"""
        success, response = self.run_test(
            "Get Pricing Plans",
            "GET",
            "plans",
            200
        )
        
        if success:
            plans = response
            print(f"   Available plans: {list(plans.keys())}")
            for plan_id, plan_data in plans.items():
                print(f"   {plan_id}: ${plan_data.get('price', 0)}/month - {plan_data.get('verifications_per_month', 0)} verifications")
        
        return success

    def test_single_email_validation(self):
        """Test single email validation"""
        test_cases = [
            ("test@gmail.com", "Valid email"),
            ("invalid@", "Invalid format"),
            ("fake@mailinator.com", "Disposable email")
        ]
        
        all_passed = True
        for email, description in test_cases:
            # Single email validation expects email as query parameter
            success, response = self.run_test(
                f"Single Email Validation - {description}",
                "POST",
                f"validate/single?email={email}",
                200
            )
            if not success:
                all_passed = False
            else:
                print(f"   Email: {email} -> Status: {response.get('status', 'unknown')}")
        
        return all_passed

    def test_bulk_email_validation(self):
        """Test bulk email validation and store job_id"""
        test_emails = [
            "test@gmail.com",
            "invalid@",
            "fake@mailinator.com",
            "user@yahoo.com",
            "badformat"
        ]
        
        success, response = self.run_test(
            "Bulk Email Validation",
            "POST",
            "validate/bulk",
            200,
            data={"emails": test_emails}
        )
        
        if success and 'job_id' in response:
            self.job_id = response['job_id']
            print(f"   Job ID: {self.job_id}")
            print(f"   Total emails: {response.get('total_emails', 0)}")
        
        return success

    def test_csv_upload(self):
        """Test CSV file upload"""
        # Create a simple CSV content
        csv_content = "email\ntest@example.com\ninvalid@\nuser@gmail.com"
        
        files = {'file': ('test_emails.csv', csv_content, 'text/csv')}
        
        success, response = self.run_test(
            "CSV Upload Validation",
            "POST",
            "validate/upload",
            200,
            files=files
        )
        
        if success:
            print(f"   CSV Job ID: {response.get('job_id', 'N/A')}")
            print(f"   Total emails from CSV: {response.get('total_emails', 0)}")
        
        return success

    def test_job_status(self):
        """Test job status retrieval"""
        if not self.job_id:
            print("❌ No job ID available for testing")
            return False
        
        # Wait a bit for processing
        print("   Waiting 3 seconds for job processing...")
        time.sleep(3)
        
        success, response = self.run_test(
            "Job Status Retrieval",
            "GET",
            f"validate/job/{self.job_id}",
            200
        )
        
        if success:
            print(f"   Job Status: {response.get('status', 'unknown')}")
            print(f"   Processed: {response.get('processed_emails', 0)}/{response.get('total_emails', 0)}")
            print(f"   Valid: {response.get('valid_count', 0)}")
            print(f"   Invalid: {response.get('invalid_count', 0)}")
            print(f"   Risky: {response.get('risky_count', 0)}")
        
        return success

    def test_job_export(self):
        """Test job results export"""
        if not self.job_id:
            print("❌ No job ID available for testing")
            return False
        
        # Wait for job completion
        print("   Waiting for job completion...")
        max_wait = 30
        wait_time = 0
        
        while wait_time < max_wait:
            try:
                response = requests.get(f"{self.base_url}/validate/job/{self.job_id}")
                if response.status_code == 200:
                    job_data = response.json()
                    if job_data.get('status') == 'completed':
                        break
                time.sleep(2)
                wait_time += 2
            except:
                break
        
        success, _ = self.run_test(
            "Job Export",
            "GET",
            f"validate/job/{self.job_id}/export",
            200
        )
        
        return success

    def test_list_jobs(self):
        """Test listing all jobs"""
        return self.run_test("List All Jobs", "GET", "validate/jobs", 200)

    def test_invalid_endpoints(self):
        """Test error handling"""
        error_tests = [
            ("Empty bulk validation", "POST", "validate/bulk", 400, {"emails": []}),
            ("Invalid job ID", "GET", "validate/job/invalid-id", 404, None),
            ("Missing file upload", "POST", "validate/upload", 422, None)
        ]
        
        all_passed = True
        for name, method, endpoint, expected_status, data in error_tests:
            success, _ = self.run_test(name, method, endpoint, expected_status, data)
            if not success:
                all_passed = False
        
        return all_passed

def main():
    print("🚀 Starting Email Validator API Tests")
    print("=" * 50)
    
    tester = EmailValidatorAPITester()
    
    # Run all tests
    tests = [
        tester.test_root_endpoint,
        tester.test_single_email_validation,
        tester.test_bulk_email_validation,
        tester.test_csv_upload,
        tester.test_job_status,
        tester.test_job_export,
        tester.test_list_jobs,
        tester.test_invalid_endpoints
    ]
    
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"❌ Test failed with exception: {str(e)}")
            tester.tests_run += 1
    
    # Print results
    print("\n" + "=" * 50)
    print(f"📊 Tests completed: {tester.tests_passed}/{tester.tests_run}")
    success_rate = (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
    print(f"📈 Success rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("🎉 Backend API tests mostly successful!")
        return 0
    else:
        print("⚠️  Backend API has significant issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())