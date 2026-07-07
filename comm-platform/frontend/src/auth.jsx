import React, { createContext, useContext, useEffect, useState } from "react";
import { connectWS, disconnectWS } from "./api.js";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("comm_user") || "null");
    } catch {
      return null;
    }
  });

  useEffect(() => {
    if (user) connectWS(user.id);
  }, [user]);

  const login = (u) => {
    localStorage.setItem("comm_user", JSON.stringify(u));
    setUser(u);
  };
  const logout = () => {
    disconnectWS();
    localStorage.removeItem("comm_user");
    setUser(null);
  };

  return <AuthCtx.Provider value={{ user, login, logout }}>{children}</AuthCtx.Provider>;
}

export const useAuth = () => useContext(AuthCtx);
