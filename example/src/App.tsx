import { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Alert,
  ScrollView,
  StyleSheet,
  SafeAreaView,
  Switch,
  Platform,
  Modal,
} from 'react-native';
import SecureStorage, {
  SecureStorageError,
  ACCESS_CONTROL,
  ERROR_CODES,
} from 'rn-secure-keystore';
import type {
  StorageOptions,
  GetItemOptions,
  HardwareSecurityInfo,
} from 'rn-secure-keystore';

interface DemoSection {
  title: string;
  expanded: boolean;
}

interface SecurityStatusItem {
  exists: boolean;
  isHardwareBacked: boolean;
  securityLevel: string;
}

interface SecurityStatus {
  [key: string]: SecurityStatusItem;
}

const CompleteLibraryDemo = () => {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const [capabilities, setCapabilities] = useState<any>(null);
  const [securityInfo, setSecurityInfo] = useState<HardwareSecurityInfo | null>(
    null
  );
  const [allKeys, setAllKeys] = useState<string[]>([]);
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus>({});

  const [withBiometric, setWithBiometric] = useState(false);
  const [securityLevel, setSecurityLevel] = useState<
    'auto' | 'strongbox' | 'hardware' | 'software'
  >('auto');
  const [allowFallback, setAllowFallback] = useState(true);

  const [accessGroup, setAccessGroup] = useState('');
  const [selectedAccessControl, setSelectedAccessControl] =
    useState<string>('');

  const [authenticatePrompt, setAuthenticatePrompt] = useState(
    'Authenticate to access secure data'
  );
  const [authenticatePromptSubtitle, setAuthenticatePromptSubtitle] = useState(
    'Use your biometric credential'
  );

  const [sections, setSections] = useState<DemoSection[]>([
    { title: 'Basic Functions', expanded: true },
    { title: 'Storage Options', expanded: true },
    { title: 'Security Functions', expanded: true },
    { title: 'Utility Functions', expanded: true },
  ]);

  const [showOptionsModal, setShowOptionsModal] = useState(false);
  const [hasShownCorruptionDialog, setHasShownCorruptionDialog] =
    useState(false);

  useEffect(() => {
    initializeDemo();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const initializeDemo = async () => {
    try {
      setIsLoading(true);

      const caps = await SecureStorage.getPlatformCapabilities();
      setCapabilities(caps);

      const hwInfo = await SecureStorage.getHardwareSecurityInfo();
      setSecurityInfo(hwInfo);

      await loadKeysAndStatus();
    } catch (error) {
      console.error('Initialization error:', error);
      showError('Initialization Failed', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadKeysAndStatus = async (showCorruptionDialog = true) => {
    try {
      const keys = await SecureStorage.getAllKeys();
      setAllKeys(keys);

      const status = await SecureStorage.getSecurityStatus();
      setSecurityStatus(status);
    } catch (error) {
      console.error('Error loading keys:', error);

      // Only show corruption dialog once and if explicitly requested
      if (
        showCorruptionDialog &&
        !hasShownCorruptionDialog &&
        error instanceof SecureStorageError &&
        error.message.includes('bad base-64')
      ) {
        setHasShownCorruptionDialog(true);
        Alert.alert(
          'Storage Corruption Detected',
          'There seems to be corrupted data. Would you like to clean up and start fresh?',
          [
            {
              text: 'Not Now',
              style: 'cancel',
              onPress: () => {
                // Set empty state to continue using the app
                setAllKeys([]);
                setSecurityStatus({});
              },
            },
            {
              text: 'Clean Up',
              style: 'destructive',
              onPress: async () => {
                try {
                  setIsLoading(true);
                  await SecureStorage.clear();
                  setAllKeys([]);
                  setSecurityStatus({});
                  setHasShownCorruptionDialog(false); // Reset for future use
                  showSuccess(
                    'Cleanup Complete',
                    'Storage has been cleaned up successfully'
                  );
                } catch (cleanupError) {
                  showError('Cleanup Failed', cleanupError);
                } finally {
                  setIsLoading(false);
                }
              },
            },
          ]
        );
      } else {
        // Silent failure - just set empty state
        setAllKeys([]);
        setSecurityStatus({});
      }
    }
  };

  const showError = (title: string, error: any) => {
    const message =
      error instanceof SecureStorageError
        ? `Code: ${error.code}\nMessage: ${error.message}`
        : error?.message || 'Unknown error occurred';

    Alert.alert(title, message);
  };

  const showSuccess = (title: string, message: string) => {
    Alert.alert(title, message);
  };

  const toggleSection = (index: number) => {
    const newSections = [...sections];
    newSections[index].expanded = !newSections[index].expanded;
    setSections(newSections);
  };

  const testSetItem = async () => {
    if (!key || !value) {
      Alert.alert('Error', 'Please enter both key and value');
      return;
    }

    try {
      setIsLoading(true);

      const options: StorageOptions = {
        withBiometric,
        authenticatePrompt,
        authenticatePromptSubtitle,
      };

      if (Platform.OS === 'android') {
        options.securityLevel = securityLevel;
        options.allowFallback = allowFallback;
      }

      if (Platform.OS === 'ios') {
        if (accessGroup) options.accessGroup = accessGroup;
        if (selectedAccessControl)
          options.accessControl = selectedAccessControl;
      }

      await SecureStorage.setItem(key, value, options);
      showSuccess('setItem Success', `Stored "${key}" successfully!`);

      // Add to local state and get detailed info
      setAllKeys((prev: string[]) => [...prev.filter((k) => k !== key), key]);
      await updateKeyInfo(key);

      setKey('');
      setValue('');
    } catch (error) {
      showError('setItem Error', error);
    } finally {
      setIsLoading(false);
    }
  };

  const testGetItem = async (keyName: string = key) => {
    if (!keyName) {
      Alert.alert('Error', 'Please enter a key name');
      return;
    }

    try {
      setIsLoading(true);

      const options: GetItemOptions = {
        authenticatePrompt,
        authenticatePromptSubtitle,
      };

      if (Platform.OS === 'ios' && accessGroup) {
        options.accessGroup = accessGroup;
      }

      const result = await SecureStorage.getItem(keyName, options);

      if (result) {
        showSuccess('getItem Success', `Key: ${keyName}\nValue: ${result}`);
      } else {
        showSuccess('getItem Result', `No data found for key: ${keyName}`);
      }
    } catch (error) {
      if (
        error instanceof SecureStorageError &&
        error.code === ERROR_CODES.AUTHENTICATION_CANCELLED
      ) {
        showSuccess('Info', 'Authentication was cancelled');
      } else {
        showError('getItem Error', error);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const testRemoveItem = async (keyName: string = key) => {
    if (!keyName) {
      Alert.alert('Error', 'Please enter a key name');
      return;
    }

    try {
      setIsLoading(true);
      await SecureStorage.removeItem(keyName);
      showSuccess('removeItem Success', `Removed key: ${keyName}`);

      // Update local state by removing the key
      setAllKeys((prev: string[]) => prev.filter((k) => k !== keyName));
      const newStatus = { ...securityStatus };
      delete newStatus[keyName];
      setSecurityStatus(newStatus);
    } catch (error) {
      showError('removeItem Error', error);
    } finally {
      setIsLoading(false);
    }
  };

  const testHasItem = async (keyName: string = key) => {
    if (!keyName) {
      Alert.alert('Error', 'Please enter a key name');
      return;
    }

    try {
      const result = await SecureStorage.hasItem(keyName);
      showSuccess(
        'hasItem Result',
        `Key "${keyName}" exists: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('hasItem Error', error);
    }
  };

  const testGetAllKeys = async () => {
    try {
      const keys = await SecureStorage.getAllKeys();
      showSuccess('getAllKeys Result', `Found ${keys.length} keys`);
      // Update local state without triggering corruption dialog
      setAllKeys(keys);
    } catch (error) {
      showError('getAllKeys Error', error);
    }
  };

  const testClear = async () => {
    Alert.alert(
      'Clear All Data',
      'This will remove all stored secure data and clean up any corrupted files. Are you sure?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear All',
          style: 'destructive',
          onPress: async () => {
            try {
              setIsLoading(true);
              await SecureStorage.clear();

              // Also clear our local state
              setAllKeys([]);
              setSecurityStatus({});

              showSuccess('clear Success', 'All data cleared successfully');
            } catch (error) {
              showError('clear Error', error);
            } finally {
              setIsLoading(false);
            }
          },
        },
      ]
    );
  };

  // Security Functions
  const testIsBiometricAvailable = async () => {
    try {
      const result = await SecureStorage.isBiometricAvailable();
      showSuccess(
        'isBiometricAvailable',
        `Biometric available: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('isBiometricAvailable Error', error);
    }
  };

  const testIsHardwareBackedAvailable = async () => {
    try {
      const result = await SecureStorage.isHardwareBackedAvailable();
      showSuccess(
        'isHardwareBackedAvailable',
        `Hardware backing: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('isHardwareBackedAvailable Error', error);
    }
  };

  const testIsStrongBoxAvailable = async () => {
    try {
      const result = await SecureStorage.isStrongBoxAvailable();
      showSuccess(
        'isStrongBoxAvailable',
        `StrongBox available: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('isStrongBoxAvailable Error', error);
    }
  };

  const testGetHardwareSecurityInfo = async () => {
    try {
      const result = await SecureStorage.getHardwareSecurityInfo();
      const info = `Hardware Backed: ${result.isHardwareBackedAvailable}\nStrongBox: ${result.isStrongBoxAvailable}\nRecommended Level: ${result.recommendedSecurityLevel}`;
      showSuccess('getHardwareSecurityInfo', info);
    } catch (error) {
      showError('getHardwareSecurityInfo Error', error);
    }
  };

  const testIsKeyHardwareBacked = async (keyName: string = key) => {
    if (!keyName) {
      Alert.alert('Error', 'Please enter a key name');
      return;
    }

    try {
      const result = await SecureStorage.isKeyHardwareBacked(keyName);
      showSuccess(
        'isKeyHardwareBacked',
        `Key "${keyName}" is hardware backed: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('isKeyHardwareBacked Error', error);
    }
  };

  const testGetKeySecurityLevel = async (keyName: string = key) => {
    if (!keyName) {
      Alert.alert('Error', 'Please enter a key name');
      return;
    }

    try {
      const result = await SecureStorage.getKeySecurityLevel(keyName);
      showSuccess(
        'getKeySecurityLevel',
        `Key "${keyName}" security level: ${result}`
      );
    } catch (error) {
      showError('getKeySecurityLevel Error', error);
    }
  };

  // Utility Functions
  const testGetRecommendedSecurityLevel = async () => {
    try {
      const result = await SecureStorage.getRecommendedSecurityLevel();
      showSuccess(
        'getRecommendedSecurityLevel',
        `Recommended level: ${result}`
      );
    } catch (error) {
      showError('getRecommendedSecurityLevel Error', error);
    }
  };

  const testIsSecurityLevelAvailable = async (
    level: 'strongbox' | 'hardware'
  ) => {
    try {
      const result = await SecureStorage.isSecurityLevelAvailable(level);
      showSuccess(
        'isSecurityLevelAvailable',
        `${level} level available: ${result ? 'Yes' : 'No'}`
      );
    } catch (error) {
      showError('isSecurityLevelAvailable Error', error);
    }
  };

  const testGetSecurityStatus = async () => {
    try {
      const result = await SecureStorage.getSecurityStatus();
      const status = Object.entries(result)
        .map(
          ([key, info]) =>
            `${key}: exists=${info.exists}, hw=${info.isHardwareBacked}, level=${info.securityLevel || 'unknown'}`
        )
        .join('\n');
      showSuccess('getSecurityStatus', status || 'No keys found');
    } catch (error) {
      showError('getSecurityStatus Error', error);
    }
  };

  const testGetPlatformCapabilities = async () => {
    try {
      const result = await SecureStorage.getPlatformCapabilities();
      const info = `Platform: ${result.platform}\nStrongBox: ${result.hasStrongBox}\nHardware Keystore: ${result.hasHardwareBackedKeystore}\nBiometrics: ${result.hasBiometrics}\nKeychain Access: ${result.hasKeychainAccessControl}`;
      showSuccess('getPlatformCapabilities', info);
    } catch (error) {
      showError('getPlatformCapabilities Error', error);
    }
  };

  const updateKeyInfo = async (keyName: string) => {
    try {
      const isHardwareBacked = await SecureStorage.isKeyHardwareBacked(keyName);
      const securityLevel = await SecureStorage.getKeySecurityLevel(keyName);

      setSecurityStatus((prev: SecurityStatus) => ({
        ...prev,
        [keyName]: {
          exists: true,
          isHardwareBacked,
          securityLevel,
        },
      }));
    } catch (error) {
      console.error(`Error getting info for key ${keyName}:`, error);
      setSecurityStatus((prev: SecurityStatus) => ({
        ...prev,
        [keyName]: {
          exists: true,
          isHardwareBacked: false,
          securityLevel: 'unknown',
        },
      }));
    }
  };

  const runDemoPreset = async (presetName: string) => {
    try {
      setIsLoading(true);

      if (presetName === 'Basic Storage') {
        await SecureStorage.setItem('demo_basic', 'Hello World!');
        showSuccess('Demo Complete', 'Basic storage completed');
        setAllKeys((prev: string[]) => [
          ...prev.filter((k) => k !== 'demo_basic'),
          'demo_basic',
        ]);
        await updateKeyInfo('demo_basic');
      }

      if (presetName === 'Biometric Storage') {
        const isBiometricAvailable = await SecureStorage.isBiometricAvailable();
        if (isBiometricAvailable) {
          await SecureStorage.setItem('demo_biometric', 'Secret Data!', {
            withBiometric: true,
            authenticatePrompt: 'Demo: Store with biometric',
          });
          showSuccess('Demo Complete', 'Biometric storage completed');
          setAllKeys((prev: string[]) => [
            ...prev.filter((k) => k !== 'demo_biometric'),
            'demo_biometric',
          ]);
          await updateKeyInfo('demo_biometric');
        } else {
          Alert.alert('Demo Info', 'Biometric not available on this device');
        }
      }

      if (presetName === 'Hardware Storage' && Platform.OS === 'android') {
        await SecureStorage.setItem('demo_hardware', 'Hardware Secured!', {
          securityLevel: 'hardware',
          allowFallback: true,
        });
        showSuccess('Demo Complete', 'Hardware storage completed');
        setAllKeys((prev: string[]) => [
          ...prev.filter((k) => k !== 'demo_hardware'),
          'demo_hardware',
        ]);
        await updateKeyInfo('demo_hardware');
      }

      if (presetName === 'StrongBox Storage' && Platform.OS === 'android') {
        await SecureStorage.setStrongBoxItem(
          'demo_strongbox',
          'Ultra Secure!',
          true
        );
        showSuccess('Demo Complete', 'StrongBox storage completed');
        setAllKeys((prev: string[]) => [
          ...prev.filter((k) => k !== 'demo_strongbox'),
          'demo_strongbox',
        ]);
        await updateKeyInfo('demo_strongbox');
      }
    } catch (error) {
      showError('Demo Error', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
      >
        <View style={styles.header}>
          <Text style={styles.title}>SecureStorage Demo</Text>
          <Text style={styles.subtitle}>Platform: {Platform.OS}</Text>
        </View>

        <View style={styles.infoCard}>
          <Text style={styles.cardTitle}>Storage Options Available</Text>
          {Platform.OS === 'ios' ? (
            <>
              <Text style={styles.infoText}>iOS Options:</Text>
              <Text style={styles.infoText}>
                • Basic Storage (hardware-backed keychain)
              </Text>
              <Text style={styles.infoText}>
                • Biometric Storage (requires authentication)
              </Text>
            </>
          ) : (
            <>
              <Text style={styles.infoText}>Android Options:</Text>
              <Text style={styles.infoText}>
                • Basic Storage (default security)
              </Text>
              <Text style={styles.infoText}>
                • Hardware Storage (explicit TEE)
              </Text>
              <Text style={styles.infoText}>
                • StrongBox Storage (security chip)
              </Text>
              <Text style={styles.infoText}>
                • Biometric Storage (any + auth)
              </Text>
            </>
          )}
        </View>

        {capabilities && securityInfo && (
          <View style={styles.infoCard}>
            <Text style={styles.cardTitle}>Device Capabilities</Text>
            <Text style={styles.infoText}>
              Platform: {capabilities.platform}
            </Text>
            <Text style={styles.infoText}>
              Hardware Keystore:{' '}
              {capabilities.hasHardwareBackedKeystore ? 'Yes' : 'No'}
            </Text>
            <Text style={styles.infoText}>
              StrongBox: {capabilities.hasStrongBox ? 'Yes' : 'No'}
            </Text>
            <Text style={styles.infoText}>
              Biometrics: {capabilities.hasBiometrics ? 'Yes' : 'No'}
            </Text>
            <Text style={styles.infoText}>
              Recommended Level: {securityInfo.recommendedSecurityLevel}
            </Text>
            <Text style={styles.infoText}>Stored Keys: {allKeys.length}</Text>
          </View>
        )}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Quick Demo Presets</Text>
          <View style={styles.presetButtons}>
            <TouchableOpacity
              style={[styles.button, styles.presetButton]}
              onPress={() => runDemoPreset('Basic Storage')}
              disabled={isLoading}
            >
              <Text style={styles.buttonText}>Basic Storage</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.button, styles.presetButton]}
              onPress={() => runDemoPreset('Biometric Storage')}
              disabled={isLoading}
            >
              <Text style={styles.buttonText}>Biometric Storage</Text>
            </TouchableOpacity>

            {Platform.OS === 'android' && (
              <>
                <TouchableOpacity
                  style={[styles.button, styles.presetButton]}
                  onPress={() => runDemoPreset('Hardware Storage')}
                  disabled={isLoading}
                >
                  <Text style={styles.buttonText}>Hardware Storage</Text>
                </TouchableOpacity>

                <TouchableOpacity
                  style={[styles.button, styles.presetButton]}
                  onPress={() => runDemoPreset('StrongBox Storage')}
                  disabled={isLoading}
                >
                  <Text style={styles.buttonText}>StrongBox Storage</Text>
                </TouchableOpacity>
              </>
            )}
          </View>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Input Data</Text>
          <TextInput
            style={styles.input}
            placeholder="Enter key name"
            value={key}
            onChangeText={setKey}
            autoCapitalize="none"
          />
          <TextInput
            style={[styles.input, styles.multilineInput]}
            placeholder="Enter value to store"
            value={value}
            onChangeText={setValue}
            multiline
            numberOfLines={3}
          />

          <TouchableOpacity
            style={[styles.button, styles.optionsButton]}
            onPress={() => setShowOptionsModal(true)}
          >
            <Text style={styles.buttonText}>Configure Options</Text>
          </TouchableOpacity>
        </View>

        {sections.map((section, index) => (
          <View key={section.title} style={styles.card}>
            <TouchableOpacity
              style={styles.sectionHeader}
              onPress={() => toggleSection(index)}
            >
              <Text style={styles.cardTitle}>{section.title}</Text>
              <Text style={styles.expandIcon}>
                {section.expanded ? '▼' : '▶'}
              </Text>
            </TouchableOpacity>

            {section.expanded && (
              <View style={styles.sectionContent}>
                {index === 0 && (
                  <>
                    <Text style={styles.sectionDescription}>
                      Core SecureStorage functions for basic operations
                    </Text>
                    <TouchableOpacity
                      style={[styles.button, styles.primaryButton]}
                      onPress={testSetItem}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>
                        1. setItem(key, value, options)
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.primaryButton]}
                      onPress={() => testGetItem()}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>
                        2. getItem(key, options)
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.primaryButton]}
                      onPress={() => testRemoveItem()}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>3. removeItem(key)</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.primaryButton]}
                      onPress={() => testHasItem()}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>4. hasItem(key)</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.primaryButton]}
                      onPress={testGetAllKeys}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>5. getAllKeys()</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.dangerButton]}
                      onPress={testClear}
                      disabled={isLoading}
                    >
                      <Text style={styles.buttonText}>6. clear()</Text>
                    </TouchableOpacity>
                  </>
                )}

                {index === 1 && (
                  <>
                    <Text style={styles.sectionDescription}>
                      Configure storage options and authentication settings
                    </Text>
                    <View style={styles.currentOptions}>
                      <Text style={styles.optionText}>
                        withBiometric: {withBiometric ? 'Yes' : 'No'}
                      </Text>
                      {Platform.OS === 'android' && (
                        <>
                          <Text style={styles.optionText}>
                            securityLevel: {securityLevel}
                          </Text>
                          <Text style={styles.optionText}>
                            allowFallback: {allowFallback ? 'Yes' : 'No'}
                          </Text>
                        </>
                      )}
                      {Platform.OS === 'ios' && selectedAccessControl && (
                        <Text style={styles.optionText}>
                          accessControl: {selectedAccessControl}
                        </Text>
                      )}
                    </View>
                    <TouchableOpacity
                      style={[styles.button, styles.optionsButton]}
                      onPress={() => setShowOptionsModal(true)}
                    >
                      <Text style={styles.buttonText}>
                        Configure Advanced Options
                      </Text>
                    </TouchableOpacity>
                  </>
                )}

                {index === 2 && (
                  <>
                    <Text style={styles.sectionDescription}>
                      Security capability detection and key security analysis
                    </Text>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={testIsBiometricAvailable}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        7. isBiometricAvailable()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={testIsHardwareBackedAvailable}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        8. isHardwareBackedAvailable()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={testIsStrongBoxAvailable}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        9. isStrongBoxAvailable()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={testGetHardwareSecurityInfo}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        10. getHardwareSecurityInfo()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={() => testIsKeyHardwareBacked()}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        11. isKeyHardwareBacked(key)
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.securityButton]}
                      onPress={() => testGetKeySecurityLevel()}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        12. getKeySecurityLevel(key)
                      </Text>
                    </TouchableOpacity>
                  </>
                )}

                {index === 3 && (
                  <>
                    <Text style={styles.sectionDescription}>
                      Utility functions for security requirements and platform
                      analysis
                    </Text>
                    <TouchableOpacity
                      style={[styles.button, styles.utilityButton]}
                      onPress={testGetRecommendedSecurityLevel}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        13. getRecommendedSecurityLevel()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.utilityButton]}
                      onPress={() => testIsSecurityLevelAvailable('strongbox')}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        14a. isSecurityLevelAvailable('strongbox')
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.utilityButton]}
                      onPress={() => testIsSecurityLevelAvailable('hardware')}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        14b. isSecurityLevelAvailable('hardware')
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.utilityButton]}
                      onPress={testGetSecurityStatus}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        15. getSecurityStatus()
                      </Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.button, styles.utilityButton]}
                      onPress={testGetPlatformCapabilities}
                      disabled={isLoading}
                    >
                      <Text style={[styles.buttonText, { color: 'white' }]}>
                        16. getPlatformCapabilities()
                      </Text>
                    </TouchableOpacity>
                  </>
                )}
              </View>
            )}
          </View>
        ))}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Stored Keys ({allKeys.length})</Text>
          {allKeys.length === 0 ? (
            <Text style={styles.emptyText}>No keys stored yet</Text>
          ) : (
            allKeys.map((keyName) => (
              <View key={keyName} style={styles.keyItem}>
                <Text style={styles.keyName}>{keyName}</Text>
                <Text style={styles.keyInfo}>
                  HW: {securityStatus[keyName]?.isHardwareBacked ? 'Yes' : 'No'}{' '}
                  | Level: {securityStatus[keyName]?.securityLevel || 'unknown'}
                </Text>
                <View style={styles.keyActions}>
                  <TouchableOpacity
                    style={[styles.actionButton, styles.viewButton]}
                    onPress={() => testGetItem(keyName)}
                  >
                    <Text style={styles.actionButtonText}>View</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.actionButton, styles.infoButton]}
                    onPress={() => testIsKeyHardwareBacked(keyName)}
                  >
                    <Text style={styles.actionButtonText}>Security</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.actionButton, styles.removeButton]}
                    onPress={() => testRemoveItem(keyName)}
                  >
                    <Text style={styles.actionButtonText}>Remove</Text>
                  </TouchableOpacity>
                </View>
              </View>
            ))
          )}
        </View>

        <Modal
          visible={showOptionsModal}
          animationType="slide"
          presentationStyle="pageSheet"
        >
          <SafeAreaView style={styles.modalContainer}>
            <ScrollView style={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Storage Options</Text>
                <TouchableOpacity
                  style={styles.closeButton}
                  onPress={() => setShowOptionsModal(false)}
                >
                  <Text style={styles.closeButtonText}>×</Text>
                </TouchableOpacity>
              </View>

              <View style={styles.optionSection}>
                <Text style={styles.optionSectionTitle}>Common Options</Text>

                <View style={styles.optionRow}>
                  <Text style={styles.optionLabel}>Biometric Protection</Text>
                  <Switch
                    value={withBiometric}
                    onValueChange={setWithBiometric}
                    trackColor={{ false: '#767577', true: '#81b0ff' }}
                    thumbColor={withBiometric ? '#f5dd4b' : '#f4f3f4'}
                  />
                </View>

                <Text style={styles.inputLabel}>Authentication Prompt:</Text>
                <TextInput
                  style={styles.modalInput}
                  value={authenticatePrompt}
                  onChangeText={setAuthenticatePrompt}
                  placeholder="Authentication prompt text"
                />

                <Text style={styles.inputLabel}>Authentication Subtitle:</Text>
                <TextInput
                  style={styles.modalInput}
                  value={authenticatePromptSubtitle}
                  onChangeText={setAuthenticatePromptSubtitle}
                  placeholder="Authentication subtitle text"
                />
              </View>

              {Platform.OS === 'android' && (
                <View style={styles.optionSection}>
                  <Text style={styles.optionSectionTitle}>Android Options</Text>

                  <View style={styles.optionRow}>
                    <Text style={styles.optionLabel}>Allow Fallback</Text>
                    <Switch
                      value={allowFallback}
                      onValueChange={setAllowFallback}
                      trackColor={{ false: '#767577', true: '#81b0ff' }}
                      thumbColor={allowFallback ? '#f5dd4b' : '#f4f3f4'}
                    />
                  </View>

                  <Text style={styles.inputLabel}>Security Level:</Text>
                  <View style={styles.securityLevelButtons}>
                    {(
                      ['auto', 'strongbox', 'hardware', 'software'] as const
                    ).map((level) => (
                      <TouchableOpacity
                        key={level}
                        style={[
                          styles.securityLevelButton,
                          securityLevel === level &&
                            styles.securityLevelButtonActive,
                        ]}
                        onPress={() => setSecurityLevel(level)}
                      >
                        <Text
                          style={[
                            styles.securityLevelText,
                            securityLevel === level &&
                              styles.securityLevelTextActive,
                          ]}
                        >
                          {level}
                        </Text>
                      </TouchableOpacity>
                    ))}
                  </View>
                </View>
              )}

              {Platform.OS === 'ios' && (
                <View style={styles.optionSection}>
                  <Text style={styles.optionSectionTitle}>iOS Options</Text>

                  <Text style={styles.inputLabel}>Access Group:</Text>
                  <TextInput
                    style={styles.modalInput}
                    value={accessGroup}
                    onChangeText={setAccessGroup}
                    placeholder="com.yourapp.sharedkeychain (optional)"
                    autoCapitalize="none"
                  />

                  <Text style={styles.inputLabel}>Access Control:</Text>
                  <View style={styles.accessControlButtons}>
                    <TouchableOpacity
                      style={[
                        styles.accessControlButton,
                        selectedAccessControl === '' &&
                          styles.accessControlButtonActive,
                      ]}
                      onPress={() => setSelectedAccessControl('')}
                    >
                      <Text style={styles.accessControlText}>None</Text>
                    </TouchableOpacity>
                    {Object.entries(ACCESS_CONTROL).map(([key, value]) => (
                      <TouchableOpacity
                        key={key}
                        style={[
                          styles.accessControlButton,
                          selectedAccessControl === value &&
                            styles.accessControlButtonActive,
                        ]}
                        onPress={() => setSelectedAccessControl(value)}
                      >
                        <Text style={styles.accessControlText}>{key}</Text>
                      </TouchableOpacity>
                    ))}
                  </View>
                </View>
              )}

              <TouchableOpacity
                style={[styles.button, styles.applyButton]}
                onPress={() => setShowOptionsModal(false)}
              >
                <Text style={styles.buttonText}>Apply Options</Text>
              </TouchableOpacity>
            </ScrollView>
          </SafeAreaView>
        </Modal>

        {isLoading && (
          <View style={styles.loadingOverlay}>
            <Text style={styles.loadingText}>Processing...</Text>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f7fa',
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    padding: 16,
    paddingBottom: 32,
  },
  header: {
    alignItems: 'center',
    marginBottom: 20,
  },
  title: {
    fontSize: 26,
    fontWeight: 'bold',
    color: '#2c3e50',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 14,
    color: '#7f8c8d',
    textAlign: 'center',
  },
  card: {
    backgroundColor: 'white',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  infoCard: {
    backgroundColor: '#e8f6ff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: '#3498db',
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#2c3e50',
    marginBottom: 0,
  },
  infoText: {
    fontSize: 14,
    color: '#34495e',
    marginBottom: 4,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
    paddingVertical: 8,
    paddingHorizontal: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#e9ecef',
  },
  expandIcon: {
    fontSize: 18,
    color: '#495057',
    fontWeight: 'bold',
    minWidth: 20,
  },
  sectionContent: {
    marginTop: 12,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#e9ecef',
  },
  sectionDescription: {
    fontSize: 14,
    color: '#7f8c8d',
    fontStyle: 'italic',
    marginBottom: 12,
  },
  currentOptions: {
    backgroundColor: '#f8f9fa',
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#e9ecef',
    marginBottom: 12,
  },
  optionText: {
    fontSize: 12,
    color: '#495057',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginBottom: 2,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    marginBottom: 12,
    backgroundColor: '#f9f9f9',
  },
  multilineInput: {
    height: 80,
    textAlignVertical: 'top',
  },
  presetButtons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  button: {
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    marginBottom: 8,
    alignItems: 'center',
  },
  primaryButton: {
    backgroundColor: '#3498db',
  },
  securityButton: {
    backgroundColor: '#e74c3c',
  },
  utilityButton: {
    backgroundColor: '#f39c12',
  },
  dangerButton: {
    backgroundColor: '#e74c3c',
  },
  presetButton: {
    backgroundColor: '#34495e',
    flex: 1,
    minWidth: '45%',
  },
  optionsButton: {
    backgroundColor: '#95a5a6',
  },
  applyButton: {
    backgroundColor: '#27ae60',
    marginTop: 20,
  },
  buttonText: {
    color: 'white',
    fontSize: 14,
    fontWeight: '600',
    textAlign: 'center',
  },
  keyItem: {
    borderWidth: 1,
    borderColor: '#ecf0f1',
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
    backgroundColor: '#fafbfc',
  },
  keyName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#2c3e50',
    marginBottom: 4,
  },
  keyInfo: {
    fontSize: 12,
    color: '#7f8c8d',
    marginBottom: 8,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  keyActions: {
    flexDirection: 'row',
    gap: 8,
  },
  actionButton: {
    flex: 1,
    paddingVertical: 6,
    paddingHorizontal: 8,
    borderRadius: 4,
    alignItems: 'center',
  },
  viewButton: {
    backgroundColor: '#3498db',
  },
  infoButton: {
    backgroundColor: '#f39c12',
  },
  removeButton: {
    backgroundColor: '#e74c3c',
  },
  actionButtonText: {
    color: 'white',
    fontSize: 11,
    fontWeight: '600',
  },
  emptyText: {
    textAlign: 'center',
    color: '#95a5a6',
    fontStyle: 'italic',
    paddingVertical: 16,
  },
  loadingOverlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: 12,
  },
  loadingText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  modalContainer: {
    flex: 1,
    backgroundColor: '#f5f7fa',
  },
  modalContent: {
    flex: 1,
    padding: 16,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#e9ecef',
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    color: '#2c3e50',
  },
  closeButton: {
    backgroundColor: '#e74c3c',
    width: 32,
    height: 32,
    borderRadius: 16,
    justifyContent: 'center',
    alignItems: 'center',
  },
  closeButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  optionSection: {
    backgroundColor: 'white',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
    elevation: 2,
  },
  optionSectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#2c3e50',
    marginBottom: 12,
  },
  optionRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 8,
    marginBottom: 8,
  },
  optionLabel: {
    fontSize: 16,
    color: '#2c3e50',
    fontWeight: '500',
  },
  inputLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#2c3e50',
    marginBottom: 6,
    marginTop: 8,
  },
  modalInput: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    backgroundColor: '#f9f9f9',
    marginBottom: 8,
  },
  securityLevelButtons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 12,
  },
  securityLevelButton: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    backgroundColor: '#ecf0f1',
    borderWidth: 1,
    borderColor: '#bdc3c7',
  },
  securityLevelButtonActive: {
    backgroundColor: '#3498db',
    borderColor: '#2980b9',
  },
  securityLevelText: {
    fontSize: 14,
    color: '#7f8c8d',
    fontWeight: '500',
  },
  securityLevelTextActive: {
    color: 'white',
    fontWeight: '600',
  },
  accessControlButtons: {
    gap: 8,
    marginBottom: 12,
  },
  accessControlButton: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 8,
    backgroundColor: '#ecf0f1',
    borderWidth: 1,
    borderColor: '#bdc3c7',
    alignItems: 'center',
  },
  accessControlButtonActive: {
    backgroundColor: '#1abc9c',
    borderColor: '#16a085',
  },
  accessControlText: {
    fontSize: 12,
    color: '#7f8c8d',
    fontWeight: '500',
  },
});

export default CompleteLibraryDemo;
