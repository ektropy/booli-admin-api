# Test Data for Booli Admin API

This directory contains sample data files for testing the bulk import functionality.

## CSV Files

### `sample-users.csv`
- **Users**: 10 sample users
- **Use Case**: Basic testing and demonstration
- **Features**: Mix of roles, some users without passwords (auto-generated), some disabled users

### `sample-users-large.csv`  
- **Users**: 30 sample users
- **Use Case**: Load testing and performance validation
- **Features**: Larger dataset with varied user configurations

## CSV Format

### Required Columns
- `email`: User's email address (must be unique)
- `first_name`: User's first name
- `last_name`: User's last name

### Optional Columns
- `username`: Username (defaults to email if not provided)
- `password`: Password (auto-generated if empty)
- `role`: Default role assignment
- `enabled`: Account enabled status (true/false, defaults to true)

## Usage Examples

### Testing with curl
```bash
# Import the basic sample file
curl -X POST http://localhost:8081/api/v1/users/import-csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test-data/sample-users.csv"

# Import the larger file for load testing
curl -X POST http://localhost:8081/api/v1/users/import-csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test-data/sample-users-large.csv"
```

### Testing with JavaScript
```javascript
const formData = new FormData();
formData.append('file', new File([csvContent], 'test-users.csv', { type: 'text/csv' }));

const response = await fetch('/api/v1/users/import-csv', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData
});

const result = await response.json();
console.log(`Imported ${result.success_count} users`);
```

## Expected Results

### `sample-users.csv` Import Results
- **Total Processed**: 10
- **Expected Success**: 10
- **Expected Failures**: 0
- **Roles Distribution**: 3 tenant-admin, 5 tenant-user, 2 tenant-viewer
- **Status Distribution**: 8 enabled, 2 disabled

### `sample-users-large.csv` Import Results  
- **Total Processed**: 30
- **Expected Success**: 30
- **Expected Failures**: 0
- **Roles Distribution**: 6 tenant-admin, 18 tenant-user, 6 tenant-viewer
- **Status Distribution**: 27 enabled, 3 disabled

## Error Testing

To test error handling, you can modify the CSV files to include:
- Duplicate email addresses
- Invalid email formats
- Missing required fields
- Malformed CSV structure

Example error scenarios:
```csv
email,first_name,last_name,username,password,role,enabled
invalid-email,Test,User,test.user,pass123,tenant-user,true
duplicate@test.com,User,One,user1,pass123,tenant-user,true
duplicate@test.com,User,Two,user2,pass456,tenant-user,true
,Missing,Email,missing.email,pass789,tenant-user,true
```

This will test the API's error handling and validation capabilities.