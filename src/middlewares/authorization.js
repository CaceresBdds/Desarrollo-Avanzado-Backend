export const authorization = (roles = []) => {
  const allowed = Array.isArray(roles) ? roles : [roles];
  return (req, res, next) => {
    if (!req.user) return res.status(401).send({ status: "error", message: "No autenticado" });
    if (allowed.length && !allowed.includes(req.user.role)) {
      return res.status(403).send({ status: "error", message: "No autorizado" });
    }
    next();
  };
};
