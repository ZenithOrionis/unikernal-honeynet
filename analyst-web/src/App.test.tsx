import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "./App";

test("renders the analyst console shell", () => {
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );

  expect(screen.getByText("Honeynet Analyst")).toBeInTheDocument();
  expect(screen.getByText("Detections")).toBeInTheDocument();
  expect(screen.getByText("Fleet")).toBeInTheDocument();
});
