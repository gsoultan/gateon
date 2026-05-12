"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuthStore = void 0;
var zustand_1 = require("zustand");
var middleware_1 = require("zustand/middleware");
exports.useAuthStore = (0, zustand_1.create)()((0, middleware_1.persist)(function (set) { return ({
    token: null,
    user: null,
    setAuth: function (token, user) { return set({ token: token, user: user }); },
    logout: function () {
        set({ token: null, user: null });
    },
}); }, {
    name: "gateon-auth",
}));
