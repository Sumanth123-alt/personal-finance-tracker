#include <iostream>
#include <fstream>
#include <vector>
#include <queue>
#include <map>
#include <unordered_map>
#include <list>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <regex>
#include <functional>
#include <cstdlib>

using namespace std;

// ------------------------- Security Utilities -------------------------
class SecurityUtils {
public:
    // Simple hash function for password hashing
    static string hashPassword(const string& password) {
        hash<string> hasher;
        size_t hashValue = hasher(password);
        return to_string(hashValue);
    }
    
    
    static string encryptData(const string& data, char key = 'S') {
        string encrypted = data;
        for (char& c : encrypted) {
            c ^= key;
        }
        return encrypted;
    }
    
    static string decryptData(const string& encryptedData, char key = 'S') {
        return encryptData(encryptedData, key); 
    }
    
    // Input validation
    static bool isValidUsername(const string& username) {
        if (username.empty() || username.length() < 3 || username.length() > 20) {
            return false;
        }
        for (char c : username) {
            if (!isalnum(c) && c != '_') {
                return false;
            }
        }
        return true;
    }
    
    static bool isValidPassword(const string& password) {
        return password.length() >= 6 && password.length() <= 50;
    }
    
    static bool isValidAmount(const string& amountStr) {
        try {
            if (amountStr.empty()) return false;
            float amount = stof(amountStr);
            return amount >= 0 && amount <= 1000000;
        } catch (...) {
            return false;
        }
    }
    
    static bool isValidTransactionType(const string& type) {
        vector<string> validTypes = {"income", "expense", "savings", "investment", "transfer"};
        return find(validTypes.begin(), validTypes.end(), type) != validTypes.end();
    }
};

// ------------------------- User Management System -------------------------
enum class UserRole {
    STANDARD,
    ADMIN
};

class User {
public:
    string username;
    string passwordHash;
    UserRole role;
    time_t createdAt;
    
    User() : role(UserRole::STANDARD), createdAt(time(0)) {}
    
    User(const string& user, const string& pass, UserRole r = UserRole::STANDARD) 
        : username(user), passwordHash(SecurityUtils::hashPassword(pass)), role(r), createdAt(time(0)) {}
    
    bool writeToFile(ofstream& ofs) const {
        try {
            // username length and username
            size_t ulen = username.length();
            ofs.write(reinterpret_cast<const char*>(&ulen), sizeof(ulen));
            ofs.write(username.c_str(), ulen);
            
            // password hash length and hash
            size_t plen = passwordHash.length();
            ofs.write(reinterpret_cast<const char*>(&plen), sizeof(plen));
            ofs.write(passwordHash.c_str(), plen);
            
            // role and creation time
            ofs.write(reinterpret_cast<const char*>(&role), sizeof(role));
            ofs.write(reinterpret_cast<const char*>(&createdAt), sizeof(createdAt));
            
            return ofs.good();
        } catch (...) {
            return false;
        }
    }
    
    bool readFromFile(ifstream& ifs) {
        try {
            size_t ulen, plen;
            
            // Reading username
            ifs.read(reinterpret_cast<char*>(&ulen), sizeof(ulen));
            if (!ifs.good() || ulen > 10000) return false;
            
            username.resize(ulen);
            ifs.read(&username[0], ulen);
            if (!ifs.good()) return false;
            
            // Reading password hash
            ifs.read(reinterpret_cast<char*>(&plen), sizeof(plen));
            if (!ifs.good() || plen > 10000) return false;
            
            passwordHash.resize(plen);
            ifs.read(&passwordHash[0], plen);
            if (!ifs.good()) return false;
            
            // Reading role and creation time
            ifs.read(reinterpret_cast<char*>(&role), sizeof(role));
            if (!ifs.good()) return false;
            ifs.read(reinterpret_cast<char*>(&createdAt), sizeof(createdAt));
            
            return ifs.good();
        } catch (...) {
            return false;
        }
    }
};

class UserManager {
private:
    vector<User> users;
    const string USER_FILE = "users.dat";
    
public:
    UserManager() {
        loadUsers();
        // Creating default admin if no users exist
        if (users.empty()) {
            createDefaultAdmin();
        }
    }
    
    void createDefaultAdmin() {
        User admin("Sumanth", "admin123", UserRole::ADMIN);
        users.push_back(admin);
        saveUsers();
        cout << "Default admin created - Username: Sumanth, Password: admin123\n";
    }
    
    bool registerUser(const string& username, const string& password, UserRole role = UserRole::STANDARD) {
        try {
            if (!SecurityUtils::isValidUsername(username)) {
                cout << "Invalid username format (3-20 chars, alphanumeric and underscore only)\n";
                return false;
            }
            
            if (!SecurityUtils::isValidPassword(password)) {
                cout << "Password must be 6-50 characters\n";
                return false;
            }
            
            // Checking if user already exists
            for (const auto& user : users) {
                if (user.username == username) {
                    cout << "Username already exists\n";
                    return false;
                }
            }
            
            User newUser(username, password, role);
            users.push_back(newUser);
            saveUsers();
            return true;
        } catch (const exception& e) {
            cerr << "Registration failed: " << e.what() << endl;
            return false;
        }
    }
    
    pair<bool, User> authenticate(const string& username, const string& password) {
        try {
            string hashedInput = SecurityUtils::hashPassword(password);
            
            for (const auto& user : users) {
                if (user.username == username && user.passwordHash == hashedInput) {
                    return {true, user};
                }
            }
            return {false, User()};
        } catch (const exception& e) {
            cerr << "Authentication error: " << e.what() << endl;
            return {false, User()};
        }
    }
    
    void loadUsers() {
        try {
            ifstream ifs(USER_FILE, ios::binary);
            if (!ifs.is_open()) {
                cout << "No existing user file found. Starting fresh.\n";
                return;
            }
            
            users.clear();
            while (ifs.peek() != EOF) {
                User user;
                if (user.readFromFile(ifs)) {
                    users.push_back(user);
                } else {
                    break;
                }
            }
            ifs.close();
            cout << "Loaded " << users.size() << " users from file.\n";
        } catch (const exception& e) {
            cerr << "Error loading users: " << e.what() << endl;
            users.clear();
        }
    }
    
    void saveUsers() {
        try {
            ofstream ofs(USER_FILE, ios::binary | ios::trunc);
            if (!ofs.is_open()) {
                throw runtime_error("Cannot open user file for writing");
            }
            
            for (const auto& user : users) {
                if (!user.writeToFile(ofs)) {
                    throw runtime_error("Failed to write user data");
                }
            }
            ofs.close();
            cout << "Saved " << users.size() << " users to file.\n";
        } catch (const exception& e) {
            cerr << "Error saving users: " << e.what() << endl;
        }
    }
};

// ------------------------- Enhanced Transaction Class -------------------------
class Transaction {
public:
    string id;
    string transactionType;
    time_t date;
    float amount;
    string description;
    string category;
    string username;
    
    Transaction() : date(time(0)), amount(0.0) {
        generateId();
    }
    
    void generateId() {
        static int counter = 0;
        counter++;
        id = "TXN" + to_string(time(0)) + "_" + to_string(counter);
    }
    
    void input(const string& currentUser) {
        string typeInput, amountStr;
        
        cout << "Available types: income, expense, savings, investment, transfer\n";
        cout << "Enter transaction type: ";
        cin >> typeInput;
        
        if (!SecurityUtils::isValidTransactionType(typeInput)) {
            throw invalid_argument("Invalid transaction type");
        }
        transactionType = typeInput;
        
        cout << "Enter amount: ";
        cin >> amountStr;
        
        if (!SecurityUtils::isValidAmount(amountStr)) {
            throw invalid_argument("Invalid amount");
        }
        amount = stof(amountStr);
        
        cout << "Enter description: ";
        cin.ignore();
        getline(cin, description);
        
        cout << "Enter category: ";
        getline(cin, category);
        
        username = currentUser;
        date = time(0);
        generateId();
    }
    
    void display() const {
        cout << "ID: " << id << "\n";
        cout << "Type: " << transactionType << "\n";
        cout << "Date: " << put_time(localtime(&date), "%Y-%m-%d %H:%M:%S") << "\n";
        cout << "Amount: $" << fixed << setprecision(2) << amount << "\n";
        cout << "Description: " << description << "\n";
        cout << "Category: " << category << "\n";
        cout << "User: " << username << "\n";
        cout << "------------------------\n";
    }
    
    bool writeToFile(ofstream& ofs) const {
        try {
            // Encrypting sensitive data before writing
            string encryptedDesc = SecurityUtils::encryptData(description);
            string encryptedCategory = SecurityUtils::encryptData(category);
            
            // Writing ID
            size_t len = id.length();
            ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
            ofs.write(id.c_str(), len);
            
            // Writing transaction type
            len = transactionType.length();
            ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
            ofs.write(transactionType.c_str(), len);
            
            // Writing date and amount
            ofs.write(reinterpret_cast<const char*>(&date), sizeof(date));
            ofs.write(reinterpret_cast<const char*>(&amount), sizeof(amount));
            
            // Writing encrypted description
            len = encryptedDesc.length();
            ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
            ofs.write(encryptedDesc.c_str(), len);
            
            // Writing encrypted category
            len = encryptedCategory.length();
            ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
            ofs.write(encryptedCategory.c_str(), len);
            
            // Writing username
            len = username.length();
            ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
            ofs.write(username.c_str(), len);
            
            return ofs.good();
        } catch (...) {
            return false;
        }
    }
    
    bool readFromFile(ifstream& ifs) {
        try {
            size_t len;
            
            // Reading ID
            ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!ifs.good() || len > 10000) return false;
            id.resize(len);
            ifs.read(&id[0], len);
            if (!ifs.good()) return false;
            
            // Reading transaction type
            ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!ifs.good() || len > 1000) return false;
            transactionType.resize(len);
            ifs.read(&transactionType[0], len);
            if (!ifs.good()) return false;
            
            // Reading date and amount
            ifs.read(reinterpret_cast<char*>(&date), sizeof(date));
            if (!ifs.good()) return false;
            ifs.read(reinterpret_cast<char*>(&amount), sizeof(amount));
            if (!ifs.good()) return false;
            
            // Reading encrypted description
            string encryptedDesc;
            ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!ifs.good() || len > 10000) return false;
            encryptedDesc.resize(len);
            ifs.read(&encryptedDesc[0], len);
            if (!ifs.good()) return false;
            description = SecurityUtils::decryptData(encryptedDesc);
            
            // Reading encrypted category
            string encryptedCategory;
            ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!ifs.good() || len > 1000) return false;
            encryptedCategory.resize(len);
            ifs.read(&encryptedCategory[0], len);
            if (!ifs.good()) return false;
            category = SecurityUtils::decryptData(encryptedCategory);
            
            // Reading username
            ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!ifs.good() || len > 1000) return false;
            username.resize(len);
            ifs.read(&username[0], len);
            
            return ifs.good();
        } catch (...) {
            return false;
        }
    }
};

// ------------------------- Advanced Data Structures -------------------------
class TransactionManager {
private:
    list<Transaction> transactions; 
    unordered_map<string, Transaction> transactionMap; 
    queue<Transaction> recentTransactions; 
    map<string, vector<Transaction>> userTransactions; 
    const string FILENAME = "transactions.dat";
    const string CSV_FILENAME = "transactions.csv";
    
    void updateDataStructures() {
        transactionMap.clear();
        userTransactions.clear();
        
        for (const auto& t : transactions) {
            transactionMap[t.id] = t;
            userTransactions[t.username].push_back(t);
        }
    }
    
public:
    void loadTransactions() {
        try {
            ifstream ifs(FILENAME, ios::binary);
            if (!ifs.is_open()) {
                cout << "No existing transaction file found. Starting fresh.\n";
                return;
            }
            
            transactions.clear();
            
            while (ifs.peek() != EOF) {
                Transaction t;
                if (t.readFromFile(ifs)) {
                    transactions.push_back(t);
                } else {
                    break;
                }
            }
            ifs.close();
            
            updateDataStructures();
            cout << "Loaded " << transactions.size() << " transactions from file.\n";
        } catch (const exception& e) {
            cerr << "Error loading transactions: " << e.what() << endl;
            transactions.clear();
            transactionMap.clear();
            userTransactions.clear();
        }
    }
    
    void saveTransactions() {
        try {
            // Saving binary format
            ofstream ofs(FILENAME, ios::binary | ios::trunc);
            if (!ofs.is_open()) {
                throw runtime_error("Cannot open transaction file for writing");
            }
            
            for (const auto& t : transactions) {
                if (!t.writeToFile(ofs)) {
                    throw runtime_error("Failed to write transaction data");
                }
            }
            ofs.close();
            
            // saving CSV format
            saveTransactionsCSV();
            
            cout << "Saved " << transactions.size() << " transactions to binary and CSV files.\n";
        } catch (const exception& e) {
            cerr << "Error saving transactions: " << e.what() << endl;
        }
    }
    
    void saveTransactionsCSV() {
        try {
            ofstream csvFile(CSV_FILENAME, ios::trunc);
            if (!csvFile.is_open()) {
                throw runtime_error("Cannot open CSV file for writing");
            }
            
            // Write header
            csvFile << "ID,Type,Date,Amount,Description,Category,Username\n";
            
            // Write data
            for (const auto& t : transactions) {
                // Format date
                stringstream dateStream;
                dateStream << put_time(localtime(&t.date), "%Y-%m-%d %H:%M:%S");
                
                // Escape quotes in description and category
                string desc = t.description;
                string cat = t.category;
                
                // Replace quotes with double quotes for CSV escaping
                size_t pos = 0;
                while ((pos = desc.find('"', pos)) != string::npos) {
                    desc.replace(pos, 1, "\"\"");
                    pos += 2;
                }
                pos = 0;
                while ((pos = cat.find('"', pos)) != string::npos) {
                    cat.replace(pos, 1, "\"\"");
                    pos += 2;
                }
                
                csvFile << t.id << ","
                       << t.transactionType << ","
                       << dateStream.str() << ","
                       << fixed << setprecision(2) << t.amount << ","
                       << "\"" << desc << "\","
                       << "\"" << cat << "\","
                       << t.username << "\n";
            }
            csvFile.close();
        } catch (const exception& e) {
            cerr << "Error saving CSV: " << e.what() << endl;
        }
    }
    
    void addTransaction(const string& currentUser) {
        try {
            Transaction t;
            t.input(currentUser);
            
            transactions.push_back(t);
            transactionMap[t.id] = t;
            userTransactions[t.username].push_back(t);
            
            // Add to recent transactions queue (keep only last 10)
            recentTransactions.push(t);
            if (recentTransactions.size() > 10) {
                recentTransactions.pop();
            }
            
            saveTransactions();
            cout << "Transaction added successfully with ID: " << t.id << endl;
        } catch (const exception& e) {
            cerr << "Error adding transaction: " << e.what() << endl;
        }
    }
    
    void displayAllTransactions(const string& currentUser, UserRole role) {
        if (transactions.empty()) {
            cout << "No transactions available.\n";
            return;
        }
        
        cout << "\n=== All Transactions ===\n";
        int count = 0;
        for (const auto& t : transactions) {
            // Standard users can only see their own transactions
            if (role == UserRole::STANDARD && t.username != currentUser) {
                continue;
            }
            t.display();
            count++;
        }
        cout << "Total transactions displayed: " << count << "\n";
    }
    
    void displayRecentTransactions() {
        if (recentTransactions.empty()) {
            cout << "No recent transactions.\n";
            return;
        }
        
        cout << "\n=== Recent Transactions ===\n";
        queue<Transaction> tempQueue = recentTransactions;
        while (!tempQueue.empty()) {
            tempQueue.front().display();
            tempQueue.pop();
        }
    }
    
    void searchById(const string& id) {
        auto it = transactionMap.find(id);
        if (it != transactionMap.end()) {
            cout << "\n=== Transaction Found ===\n";
            it->second.display();
        } else {
            cout << "Transaction with ID " << id << " not found.\n";
        }
    }
    
    void searchByDate(const string& dateStr, const string& currentUser, UserRole role) {
        bool found = false;
        cout << "\n=== Transactions on " << dateStr << " ===\n";
        
        for (const auto& t : transactions) {
            if (role == UserRole::STANDARD && t.username != currentUser) {
                continue;
            }
            
            stringstream ss;
            ss << put_time(localtime(&t.date), "%Y-%m-%d");
            if (ss.str() == dateStr) {
                t.display();
                found = true;
            }
        }
        
        if (!found) cout << "No transactions found on that date.\n";
    }
    
    void searchByType(const string& type, const string& currentUser, UserRole role) {
        bool found = false;
        cout << "\n=== Transactions of type: " << type << " ===\n";
        
        for (const auto& t : transactions) {
            if (role == UserRole::STANDARD && t.username != currentUser) {
                continue;
            }
            
            if (t.transactionType == type) {
                t.display();
                found = true;
            }
        }
        
        if (!found) cout << "No transactions found with that type.\n";
    }
    
    void showTotalByType(const string& type, const string& currentUser, UserRole role) {
        float total = 0.0;
        int count = 0;
        
        for (const auto& t : transactions) {
            if (role == UserRole::STANDARD && t.username != currentUser) {
                continue;
            }
            
            if (t.transactionType == type) {
                total += t.amount;
                count++;
            }
        }
        
        if (count > 0) {
            cout << "Total for transaction type \"" << type << "\": $" 
                 << fixed << setprecision(2) << total 
                 << " (" << count << " transactions)\n";
        } else {
            cout << "No transactions found with that type.\n";
        }
    }
    
    void generateReport(const string& currentUser, UserRole role) {
        cout << "\n=== Financial Report ===\n";
        
        float totalIncome = 0, totalExpense = 0, totalSavings = 0, totalInvestment = 0;
        int transactionCount = 0;
        
        for (const auto& t : transactions) {
            if (role == UserRole::STANDARD && t.username != currentUser) {
                continue;
            }
            
            transactionCount++;
            if (t.transactionType == "income") totalIncome += t.amount;
            else if (t.transactionType == "expense") totalExpense += t.amount;
            else if (t.transactionType == "savings") totalSavings += t.amount;
            else if (t.transactionType == "investment") totalInvestment += t.amount;
        }
        
        cout << "Total Transactions: " << transactionCount << "\n";
        cout << "Total Income: $" << fixed << setprecision(2) << totalIncome << "\n";
        cout << "Total Expenses: $" << totalExpense << "\n";
        cout << "Total Savings: $" << totalSavings << "\n";
        cout << "Total Investments: $" << totalInvestment << "\n";
        cout << "Net Worth: $" << (totalIncome - totalExpense + totalSavings + totalInvestment) << "\n";
    }
    
    void deleteTransaction(const string& id, UserRole role) {
        if (role != UserRole::ADMIN) {
            cout << "Access denied. Only administrators can delete transactions.\n";
            return;
        }
        
        auto it = find_if(transactions.begin(), transactions.end(),
                         [&id](const Transaction& t) { return t.id == id; });
        
        if (it != transactions.end()) {
            transactionMap.erase(it->id);
            transactions.erase(it);
            updateDataStructures();
            saveTransactions();
            cout << "Transaction deleted successfully.\n";
        } else {
            cout << "Transaction not found.\n";
        }
    }
};

// ------------------------- Main Application -------------------------
class FinanceTracker {
private:
    UserManager userManager;
    TransactionManager transactionManager;
    User currentUser;
    bool isLoggedIn;
    
public:
    FinanceTracker() : isLoggedIn(false) {
        transactionManager.loadTransactions();
    }
    
    bool login() {
        cout << "\n=== Personal Finance Tracker - Login Required ===\n";
        cout << "1. Login\n2. Register New User\n3. Exit\n";
        cout << "Choose option: ";
        
        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "Invalid input. Please enter a number.\n";
            return login();
        }
        
        switch (choice) {
            case 1:
                return performLogin();
            case 2:
                return performRegistration();
            case 3:
                cout << "Goodbye!\n";
                return false;
            default:
                cout << "Invalid choice.\n";
                return login();
        }
    }
    
    bool performLogin() {
        string username, password;
        int attempts = 0;
        const int maxAttempts = 3;
        
        while (attempts < maxAttempts) {
            cout << "Username: ";
            cin >> username;
            cout << "Password: ";
            cin >> password;
            
            auto [success, user] = userManager.authenticate(username, password);
            if (success) {
                currentUser = user;
                isLoggedIn = true;
                cout << "Login successful! Welcome, " << username << "!\n";
                if (user.role == UserRole::ADMIN) {
                    cout << "Administrator privileges granted.\n";
                }
                return true;
            } else {
                attempts++;
                cout << "Invalid credentials. Attempts remaining: " << (maxAttempts - attempts) << "\n";
            }
        }
        
        cout << "Maximum login attempts exceeded. Access denied.\n";
        return false;
    }
    
    bool performRegistration() {
        string username, password, confirmPassword;
        
        cout << "=== User Registration ===\n";
        cout << "Username (3-20 characters, alphanumeric and underscore only): ";
        cin >> username;
        
        cout << "Password (6-50 characters): ";
        cin >> password;
        
        cout << "Confirm Password: ";
        cin >> confirmPassword;
        
        if (password != confirmPassword) {
            cout << "Passwords do not match.\n";
            return false;
        }
        
        if (userManager.registerUser(username, password)) {
            cout << "Registration successful! Please login.\n";
            return performLogin();
        } else {
            cout << "Registration failed.\n";
            return false;
        }
    }
    
    void showMenu() {
        cout << "\n=== Personal Finance Tracker Menu ===\n";
        cout << "1. Add Transaction\n";
        cout << "2. View All Transactions\n";
        cout << "3. View Recent Transactions\n";
        cout << "4. Search by Transaction ID\n";
        cout << "5. Search by Date\n";
        cout << "6. Search by Type\n";
        cout << "7. Show Total by Type\n";
        cout << "8. Generate Financial Report\n";
        
        if (currentUser.role == UserRole::ADMIN) {
            cout << "9. Delete Transaction (Admin Only)\n";
        }
        
        cout << "0. Logout and Exit\n";
        cout << "Enter choice: ";
    }
    
    void run() {
        if (!login()) return;
        
        int choice;
        do {
            showMenu();
            if (!(cin >> choice)) {
                cin.clear();
                cin.ignore(10000, '\n');
                cout << "Invalid input. Please enter a number.\n";
                continue;
            }
            
            try {
                switch (choice) {
                    case 1:
                        transactionManager.addTransaction(currentUser.username);
                        break;
                    case 2:
                        transactionManager.displayAllTransactions(currentUser.username, currentUser.role);
                        break;
                    case 3:
                        transactionManager.displayRecentTransactions();
                        break;
                    case 4: {
                        string id;
                        cout << "Enter Transaction ID: ";
                        cin >> id;
                        transactionManager.searchById(id);
                        break;
                    }
                    case 5: {
                        string date;
                        cout << "Enter date (YYYY-MM-DD): ";
                        cin >> date;
                        transactionManager.searchByDate(date, currentUser.username, currentUser.role);
                        break;
                    }
                    case 6: {
                        string type;
                        cout << "Enter transaction type: ";
                        cin >> type;
                        transactionManager.searchByType(type, currentUser.username, currentUser.role);
                        break;
                    }
                    case 7: {
                        string type;
                        cout << "Enter transaction type: ";
                        cin >> type;
                        transactionManager.showTotalByType(type, currentUser.username, currentUser.role);
                        break;
                    }
                    case 8:
                        transactionManager.generateReport(currentUser.username, currentUser.role);
                        break;
                    case 9:
                        if (currentUser.role == UserRole::ADMIN) {
                            string id;
                            cout << "Enter Transaction ID to delete: ";
                            cin >> id;
                            transactionManager.deleteTransaction(id, currentUser.role);
                        } else {
                            cout << "Invalid choice.\n";
                        }
                        break;
                    case 0:
                        cout << "Logging out... Goodbye!\n";
                        break;
                    default:
                        cout << "Invalid choice. Please try again.\n";
                }
            } catch (const exception& e) {
                cerr << "Error: " << e.what() << endl;
                cout << "Please try again.\n";
                cin.clear();
                cin.ignore(10000, '\n');
            }
            
        } while (choice != 0);
    }
};

// ------------------------- Main Function -------------------------
int main() {
    try {
        cout << "=== Personal Finance Tracker===\n";
        cout << "Created by: Sumanth\n";
        cout << "Features: Secure Authentication, File Handling, Advanced Data Structures\n\n";
        
        FinanceTracker app;
        app.run();
        
    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    } catch (...) {
        cerr << "Unknown fatal error occurred." << endl;
        return 1;
    }
    
    return 0;
}