import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { StatusBadge } from '../components/StatusBadge';

describe('YouTube Isolation Manager Desktop UI', () => {
  it('renders application brand and 5 primary navigation tabs', async () => {
    render(<App />);

    expect(screen.getByText('YouTube Isolation')).toBeInTheDocument();
    expect(screen.getByText('Desktop Manager v1.0')).toBeInTheDocument();

    // Verify exactly 5 primary navigation tabs
    expect(screen.getByRole('button', { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /environments/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /network/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /channels/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /settings/i })).toBeInTheDocument();
  });

  it('navigates seamlessly between all 5 screens (REG-001)', async () => {
    render(<App />);

    // 1. Overview Screen
    expect(screen.getByText('System Overview')).toBeInTheDocument();

    // 2. Navigate to Environments
    fireEvent.click(screen.getByRole('button', { name: /environments/i }));
    await waitFor(() => {
      expect(screen.getByText('Virtual Environments')).toBeInTheDocument();
      expect(screen.getByText('Create Environment')).toBeInTheDocument();
    });

    // 3. Navigate to Network
    fireEvent.click(screen.getByRole('button', { name: /network/i }));
    await waitFor(() => {
      expect(screen.getByText('Network & Egress Diagnostics')).toBeInTheDocument();
      expect(screen.getByText('Add Network Endpoint')).toBeInTheDocument();
    });

    // 4. Navigate to Channels
    fireEvent.click(screen.getByRole('button', { name: /channels/i }));
    await waitFor(() => {
      expect(screen.getByText('YouTube Channel Registry')).toBeInTheDocument();
      expect(screen.getByText('Register Channel')).toBeInTheDocument();
    });

    // 5. Navigate to Settings
    fireEvent.click(screen.getByRole('button', { name: /settings/i }));
    await waitFor(() => {
      expect(screen.getByText('Application Settings')).toBeInTheDocument();
      expect(screen.getByText(/Integration/i)).toBeInTheDocument();
    });
  });

  it('renders semantic status badges correctly', () => {
    const { container: runningBadge } = render(<StatusBadge status="RUNNING" />);
    expect(runningBadge.textContent).toContain('RUNNING');

    const { container: terminatedBadge } = render(<StatusBadge status="TERMINATED" />);
    expect(terminatedBadge.textContent).toContain('TERMINATED');

    const { container: verifiedBadge } = render(<StatusBadge status="VERIFIED" />);
    expect(verifiedBadge.textContent).toContain('VERIFIED');
  });

  it('opens and cancels Create Environment modal', async () => {
    render(<App />);

    fireEvent.click(screen.getByRole('button', { name: /environments/i }));
    await waitFor(() => {
      expect(screen.getByText('Create Environment')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Create Environment'));

    expect(screen.getByText('Create Isolated Environment')).toBeInTheDocument();
    expect(screen.getByText('Guest Operating System')).toBeInTheDocument();

    // Cancel modal
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByText('Create Isolated Environment')).not.toBeInTheDocument();
    });
  });

  it('displays native secret vault test tool in Settings screen', async () => {
    render(<App />);

    fireEvent.click(screen.getByRole('button', { name: /settings/i }));
    await waitFor(() => {
      expect(screen.getByText(/Encrypted Secret Vault/i)).toBeInTheDocument();
      expect(screen.getByText('Run Cryptographic Test')).toBeInTheDocument();
    });
  });
});
