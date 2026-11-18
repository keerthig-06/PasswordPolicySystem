
import { useState } from "react";
import "./App.css";

const API = process.env.REACT_APP_API ||"https://passwordpolicysystem.onrender.com";

function App() {
  const [page, setPage] = useState("register");

  // Registration states
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");

  // Login states
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginMessage, setLoginMessage] = useState("");

  // User dashboard
  const [userData, setUserData] = useState(null);

  // Admin states
  const [unlockEmail, setUnlockEmail] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [unlockMessage, setUnlockMessage] = useState("");
  const [users, setUsers] = useState([]);
  const [adminMessage, setAdminMessage] = useState("");

  // Password policy
  const rules = [
    {
      text: "Minimum 8 characters",
      valid: password.length >= 8
    },
    {
      text: "One uppercase letter",
      valid: /[A-Z]/.test(password)
    },
    {
      text: "One lowercase letter",
      valid: /[a-z]/.test(password)
    },
    {
      text: "One number",
      valid: /[0-9]/.test(password)
    },
    {
      text: "One special character",
      valid: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    }
  ];

  // USER REGISTRATION
  const handleRegister = async (e) => {
    e.preventDefault();

    if (!rules.every((rule) => rule.valid)) {
      setMessage("Password does not satisfy the policy!");
      return;
    }

    if (password !== confirmPassword) {
      setMessage("Passwords do not match!");
      return;
    }

    try {
      const response = await fetch(
        "https://passwordpolicysystem.onrender.com",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            username,
            email,
            password,
            confirmPassword
          })
        }
      );

      const data = await response.json();

      if (response.ok) {
        setMessage(data.message);
        setUsername("");
        setEmail("");
        setPassword("");
        setConfirmPassword("");
      } else {
        setMessage(data.message);
      }
    } catch (error) {
      setMessage("Backend connection failed!");
    }
  };

  // USER LOGIN
  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(
        "https://passwordpolicysystem.onrender.com",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            email: loginEmail,
            password: loginPassword
          })
        }
      );

      const data = await response.json();

      if (response.ok) {
        setLoginMessage(data.message);
        setUserData(data.user);
        setLoginPassword("");
        setPage("dashboard");
      } else {
        setLoginMessage(
          data.remainingAttempts !== undefined
            ? `${data.message}. Remaining attempts: ${data.remainingAttempts}`
            : data.message
        );
      }
    } catch (error) {
      setLoginMessage("Backend connection failed!");
    }
  };

  // USER LOGOUT
  const handleLogout = () => {
    setUserData(null);
    setLoginEmail("");
    setLoginPassword("");
    setLoginMessage("");
    setPage("login");
  };

  // ADMIN ACCOUNT UNLOCK
  const handleUnlock = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(
        "https://passwordpolicysystem.onrender.com",
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "admin-key": adminKey
          },
          body: JSON.stringify({
            email: unlockEmail
          })
        }
      );

      const data = await response.json();

      setUnlockMessage(data.message);

      if (response.ok) {
        setUserData((previousData) => {
          if (
            previousData &&
            previousData.email === data.user.email
          ) {
            return {
              ...previousData,
              ...data.user
            };
          }

          return previousData;
        });

        setUnlockEmail("");

        if (users.length > 0) {
          handleFetchUsers();
        }
      }
    } catch (error) {
      setUnlockMessage("Backend connection failed!");
    }
  };

  // FETCH ALL USERS
  const handleFetchUsers = async () => {
    if (!adminKey) {
      setAdminMessage("Please enter Admin Key!");
      return;
    }

    try {
      const response = await fetch(
        "https://passwordpolicysystem.onrender.com",
        {
          method: "GET",
          headers: {
            "admin-key": adminKey
          }
        }
      );

      const data = await response.json();

      if (response.ok) {
        setUsers(data.users);
        setAdminMessage(data.message);
      } else {
        setAdminMessage(data.message);
        setUsers([]);
      }
    } catch (error) {
      setAdminMessage("Backend connection failed!");
    }
  };

  return (
    <div className="container">

      <h1>Password Policy Validation System</h1>

      {/* NAVIGATION */}
      <div className="menu">

        <button onClick={() => setPage("register")}>
          Register
        </button>

        <button onClick={() => setPage("login")}>
          Login
        </button>

        <button onClick={() => setPage("dashboard")}>
          User Dashboard
        </button>

        <button onClick={() => setPage("admin")}>
          Admin Dashboard
        </button>

      </div>

      {/* REGISTRATION PAGE */}
      {page === "register" && (
        <div className="form-box">

          <h2>User Registration</h2>

          <form onSubmit={handleRegister}>

            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />

            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />

            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />

            <h3>Password Policy</h3>

            {rules.map((rule, index) => (
              <p
                key={index}
                className={rule.valid ? "valid-rule" : "invalid-rule"}
              >
                {rule.valid ? "✓" : "✗"} {rule.text}
              </p>
            ))}

            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) =>
                setConfirmPassword(e.target.value)
              }
              required
            />

            <button type="submit">
              Register
            </button>

          </form>

          <p>{message}</p>

        </div>
      )}

      {/* LOGIN PAGE */}
      {page === "login" && (
        <div className="form-box">

          <h2>User Login</h2>

          <form onSubmit={handleLogin}>

            <input
              type="email"
              placeholder="Email"
              value={loginEmail}
              onChange={(e) => setLoginEmail(e.target.value)}
              required
            />

            <input
              type="password"
              placeholder="Password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              required
            />

            <button type="submit">
              Login
            </button>

          </form>

          <p>{loginMessage}</p>

        </div>
      )}

      {/* USER SECURITY DASHBOARD */}
      {page === "dashboard" && (
        <div className="dashboard-container">

          <div className="dashboard-heading">
            <h2>Security Dashboard</h2>
            <p>Monitor your account security and login activity</p>
          </div>

          {userData ? (
            <>

              <div className="dashboard-profile">

                <div className="profile-icon">👤</div>

                <div>
                  <h3>{userData.username}</h3>
                  <p>{userData.email}</p>
                </div>

                <span className={
                  userData.accountLocked
                    ? "status-badge locked"
                    : "status-badge active"
                }>
                  {userData.accountLocked ? "Locked" : "Active"}
                </span>

              </div>

              <div className="dashboard-grid">

                <div className="dashboard-card">
                  <span className="card-icon">🔐</span>
                  <h3>Account Status</h3>
                  <p>{userData.accountStatus}</p>
                </div>

                <div className="dashboard-card">
                  <span className="card-icon">❌</span>
                  <h3>Total Failed Attempts</h3>
                  <p>
                    {(userData.loginHistory || []).filter(
                      (item) => item.status === "Failed Attempt"
                    ).length}
                  </p>
                </div>

                <div className="dashboard-card">
                  <span className="card-icon">🔄</span>
                  <h3>Consecutive Failed Attempts</h3>
                  <p>{userData.failedAttempts}</p>
                </div>

                <div className="dashboard-card">
                  <span className="card-icon">🛡️</span>
                  <h3>Account Lock Status</h3>
                  <p className={
                    userData.accountLocked
                      ? "danger-text"
                      : "success-text"
                  }>
                    {userData.accountLocked ? "Locked" : "Unlocked"}
                  </p>
                </div>

              </div>

              <div className="history-section">

                <h3>Login History</h3>

                {(userData.loginHistory || []).length > 0 ? (
                  (userData.loginHistory || []).map((item, index) => (
                    <div className="history-item" key={index}>
                      <span>{item.status}</span>
                      <small>
                        {new Date(item.date).toLocaleString()}
                      </small>
                    </div>
                  ))
                ) : (
                  <p>No login history available.</p>
                )}

              </div>

              <button
                className="logout-button"
                onClick={handleLogout}
              >
                Logout
              </button>

            </>
          ) : (
            <div className="dashboard-card">
              <p>Please login to view your dashboard.</p>
            </div>
          )}

        </div>
      )}

      {/* ADMIN DASHBOARD */}
      {page === "admin" && (
        <div className="dashboard-container">

          <div className="dashboard-heading">
            <h2>Admin Dashboard</h2>
            <p>Manage registered users and account security</p>
          </div>

          <div className="admin-control-card">

            <h3>Admin Authentication</h3>

            <input
              type="password"
              placeholder="Enter Admin Key"
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
            />

            <button onClick={handleFetchUsers}>
              View All Users
            </button>

            <p>{adminMessage}</p>

          </div>

          <div className="admin-users-section">

            <h3>Registered Users</h3>

            <p className="section-description">
              View user accounts and their security status
            </p>

            {users.length > 0 ? (
              <div className="admin-users-grid">

                {users.map((user) => (
                  <div className="admin-user-card" key={user._id}>

                    <div className="admin-user-header">

                      <div className="profile-icon">👤</div>

                      <div>
                        <h3>{user.username}</h3>
                        <p>{user.email}</p>
                      </div>

                    </div>

                    <div className="user-info-row">
                      <span>Account Status</span>
                      <strong>{user.accountStatus}</strong>
                    </div>

                    <div className="user-info-row">
                      <span>Failed Attempts</span>
                      <strong>{user.failedAttempts}</strong>
                    </div>

                    <div className="user-info-row">
                      <span>Lock Status</span>
                      <strong className={
                        user.accountLocked
                          ? "danger-text"
                          : "success-text"
                      }>
                        {user.accountLocked ? "Locked" : "Unlocked"}
                      </strong>
                    </div>

                    {user.accountLocked && (
                      <button
                        className="unlock-select-button"
                        onClick={() => {
                          setUnlockEmail(user.email);
                          setUnlockMessage("");
                        }}
                      >
                        Select for Unlock
                      </button>
                    )}

                  </div>
                ))}

              </div>
            ) : (
              <div className="dashboard-card">
                <p>
                  No users to display. Enter Admin Key and click View All Users.
                </p>
              </div>
            )}

          </div>

          <div className="admin-control-card unlock-card">

            <h3>Unlock User Account</h3>

            <form onSubmit={handleUnlock}>

              <input
                type="email"
                placeholder="User Email"
                value={unlockEmail}
                onChange={(e) => setUnlockEmail(e.target.value)}
                required
              />

              <button type="submit">
                Unlock Account
              </button>

            </form>

            <p>{unlockMessage}</p>

          </div>

        </div>
      )}

    </div>
  );
}

export default App;
