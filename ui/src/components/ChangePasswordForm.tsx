// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import React, { useState } from "react";
import { Alert, Button, Group, PasswordInput, Stack } from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconAlertCircle } from "@tabler/icons-react";
import { changeOwnPassword, resetPassword } from "./passwordChange";

interface ChangePasswordFormProps {
  userId: string;
  /** The signed-in user's own account, which needs its current password. */
  own: boolean;
  onChanged: () => void;
  submitLabel?: string;
}

/**
 * Changes a password: your own, with the current one, or another account's
 * as its administrator. The Profile page and the Users page both use it, so
 * the step-up, the loading state and the error sentences cannot drift apart.
 */
export const ChangePasswordForm: React.FC<ChangePasswordFormProps> = ({
  userId,
  own,
  onChanged,
  submitLabel = "Change password",
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const form = useForm({
    initialValues: { currentPassword: "", password: "", confirmPassword: "" },
    validate: {
      currentPassword: (value) => (own && value.length === 0 ? "Enter your current password" : null),
      password: (value) => (value.length < 6 ? "Password must be at least 6 characters" : null),
      confirmPassword: (value, values) => (value !== values.password ? "Passwords do not match" : null),
    },
  });

  const submit = async (values: typeof form.values) => {
    setLoading(true);
    setError(null);
    const outcome = own
      ? await changeOwnPassword(userId, values.currentPassword, values.password)
      : await resetPassword(userId, values.password);
    setLoading(false);
    // Nothing typed here is kept past the attempt.
    form.reset();
    if (outcome.ok) {
      onChanged();
    } else {
      setError(outcome.message);
    }
  };

  return (
    <form onSubmit={form.onSubmit((values) => void submit(values))}>
      <Stack gap="sm">
        {own && (
          <PasswordInput
            label="Current password"
            placeholder="Enter your current password"
            autoComplete="current-password"
            required
            {...form.getInputProps("currentPassword")}
          />
        )}
        <PasswordInput
          label="New password"
          placeholder="Enter new password"
          autoComplete="new-password"
          required
          {...form.getInputProps("password")}
        />
        <PasswordInput
          label="Confirm new password"
          placeholder="Re-enter new password"
          autoComplete="new-password"
          required
          {...form.getInputProps("confirmPassword")}
        />
        {error && (
          <Alert color="red" variant="light" icon={<IconAlertCircle size="1rem" />} role="alert">
            {error}
          </Alert>
        )}
        <Group justify="flex-end" mt="xs">
          <Button type="submit" loading={loading}>
            {submitLabel}
          </Button>
        </Group>
      </Stack>
    </form>
  );
};
